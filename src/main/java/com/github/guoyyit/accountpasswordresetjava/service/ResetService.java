package com.github.guoyyit.accountpasswordresetjava.service;

import com.github.guoyyit.accountpasswordresetjava.config.AppProperties;
import com.github.guoyyit.accountpasswordresetjava.delivery.LocalDeliveryService;
import com.github.guoyyit.accountpasswordresetjava.model.Account;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.model.PasswordHistoryEntry;
import com.github.guoyyit.accountpasswordresetjava.model.ResetToken;
import com.github.guoyyit.accountpasswordresetjava.repository.AccountRepository;
import com.github.guoyyit.accountpasswordresetjava.repository.PasswordHistoryRepository;
import com.github.guoyyit.accountpasswordresetjava.repository.ResetTokenRepository;
import com.github.guoyyit.accountpasswordresetjava.web.ApiException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class ResetService {

    /** 统一拒绝文案：不泄露凭据是已使用、已过期还是根本不存在 */
    public static final String INVALID_CREDENTIAL_MESSAGE = "invalid or expired reset credential";

    private static final Pattern CODE_FORMAT = Pattern.compile("^\\d{6}$");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AccountRepository accountRepository;
    private final ResetTokenRepository resetTokenRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordService passwordService;
    private final TokenDigestService tokenDigestService;
    private final SessionService sessionService;
    private final AccountService accountService;
    private final AuditService auditService;
    private final ResetAttemptService resetAttemptService;
    private final RateLimiter rateLimiter;
    private final LocalDeliveryService deliveryService;
    private final AppProperties properties;

    public ResetService(AccountRepository accountRepository,
                        ResetTokenRepository resetTokenRepository,
                        PasswordHistoryRepository passwordHistoryRepository,
                        PasswordService passwordService,
                        TokenDigestService tokenDigestService,
                        SessionService sessionService,
                        AccountService accountService,
                        AuditService auditService,
                        ResetAttemptService resetAttemptService,
                        RateLimiter rateLimiter,
                        LocalDeliveryService deliveryService,
                        AppProperties properties) {
        this.accountRepository = accountRepository;
        this.resetTokenRepository = resetTokenRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.passwordService = passwordService;
        this.tokenDigestService = tokenDigestService;
        this.sessionService = sessionService;
        this.accountService = accountService;
        this.auditService = auditService;
        this.resetAttemptService = resetAttemptService;
        this.rateLimiter = rateLimiter;
        this.deliveryService = deliveryService;
        this.properties = properties;
    }

    /**
     * 申请重置凭据。无论账户是否存在，对外表现一致（由控制器返回统一文案）。
     * 通过账户行悲观锁保证并发申请串行化：同一账户任一时刻最多一个可用凭据。
     */
    @Transactional
    public void requestReset(String username) {
        String normalized = AccountService.normalizeUsername(username);
        if (!rateLimiter.tryAcquire("reset-request:" + normalized,
                properties.getResetRequestMax(), properties.getResetRequestWindow())) {
            auditService.record(AuditEventType.RESET_REQUEST_RATE_LIMITED, null, normalized,
                    "reset request rate limited");
            throw ApiException.tooManyRequests("too many reset requests, please try again later");
        }
        Account account = accountRepository.findByUsernameForUpdate(normalized).orElse(null);
        if (account == null) {
            auditService.record(AuditEventType.RESET_REQUESTED, null, normalized,
                    "reset requested for unknown account");
            return;
        }
        Instant now = Instant.now();
        List<ResetToken> existing = resetTokenRepository.findByAccountId(account.getId());
        for (ResetToken token : existing) {
            if (token.getUsedAt() == null && token.getInvalidatedAt() == null) {
                token.invalidate(now);
            }
        }
        String code = generateCode();
        ResetToken token = new ResetToken(tokenDigestService.digest(code), account, now,
                now.plus(properties.getResetTokenTtl()));
        resetTokenRepository.save(token);
        deliveryService.deliver(normalized, "password reset code: " + code
                + " (expires in " + properties.getResetTokenTtl().toMinutes() + " minutes)");
        auditService.record(AuditEventType.RESET_REQUESTED, account.getId(), normalized,
                "reset credential issued");
    }

    /**
     * 校验凭据是否可用（只读检查，不消耗凭据）。任何失败统一拒绝。
     */
    @Transactional
    public void verify(String username, String code) {
        ResetToken token = requireUsableToken(username, code, false);
        auditService.record(AuditEventType.RESET_VERIFY_SUCCESS,
                token.getAccount().getId(), token.getAccount().getUsername(), "credential verified");
    }

    /**
     * 使用凭据设置新口令：校验凭据 -> 强度与历史口令检查 -> 更新口令 ->
     * 凭据标记已用 -> 撤销该账户全部会话。
     */
    @Transactional
    public void confirm(String username, String code, String newPassword) {
        ResetToken token = requireUsableToken(username, code, true);
        Account account = token.getAccount();
        passwordService.assertStrength(newPassword);
        if (accountService.isPasswordReused(account, newPassword)) {
            auditService.record(AuditEventType.RESET_CONFIRM_FAILURE, account.getId(),
                    account.getUsername(), "new password reused from history");
            throw ApiException.badRequest("new password must differ from previously used passwords");
        }
        Instant now = Instant.now();
        String hash = passwordService.hash(newPassword);
        account.setPasswordHash(hash);
        passwordHistoryRepository.save(new PasswordHistoryEntry(account, hash, now));
        token.markUsed(now);
        int revoked = sessionService.revokeAllForAccount(account.getId());
        auditService.record(AuditEventType.SESSIONS_REVOKED_ALL, account.getId(),
                account.getUsername(), revoked + " session(s) revoked after password reset");
        auditService.record(AuditEventType.RESET_CONFIRM_SUCCESS, account.getId(),
                account.getUsername(), "password reset completed");
    }

    private ResetToken requireUsableToken(String username, String code, boolean forConfirm) {
        String normalized = AccountService.normalizeUsername(username);
        AuditEventType failureType = forConfirm
                ? AuditEventType.RESET_CONFIRM_FAILURE
                : AuditEventType.RESET_VERIFY_FAILURE;
        if (code == null || !CODE_FORMAT.matcher(code).matches()) {
            auditService.record(failureType, null, normalized, "malformed credential");
            throw ApiException.badRequest(INVALID_CREDENTIAL_MESSAGE);
        }
        Account account = accountRepository.findByUsername(normalized).orElse(null);
        if (account == null) {
            auditService.record(failureType, null, normalized, "unknown account");
            throw ApiException.badRequest(INVALID_CREDENTIAL_MESSAGE);
        }
        String hash = tokenDigestService.digest(code);
        ResetToken token = (forConfirm
                ? resetTokenRepository.findByTokenHashForUpdate(hash)
                : resetTokenRepository.findByTokenHash(hash)).orElse(null);
        Instant now = Instant.now();
        if (token == null || !token.getAccount().getId().equals(account.getId())) {
            resetAttemptService.registerFailedAttempt(account.getId(), now);
            auditService.record(failureType, account.getId(), normalized, "credential mismatch");
            throw ApiException.badRequest(INVALID_CREDENTIAL_MESSAGE);
        }
        if (!token.isUsable(now)) {
            auditService.record(failureType, account.getId(), normalized,
                    "credential used, expired or invalidated");
            throw ApiException.badRequest(INVALID_CREDENTIAL_MESSAGE);
        }
        return token;
    }

    private static String generateCode() {
        return String.format("%06d", RANDOM.nextInt(1_000_000));
    }
}
