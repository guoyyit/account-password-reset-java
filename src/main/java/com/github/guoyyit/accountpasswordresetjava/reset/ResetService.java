package com.github.guoyyit.accountpasswordresetjava.reset;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.github.guoyyit.accountpasswordresetjava.account.AccountRepository;
import com.github.guoyyit.accountpasswordresetjava.account.AccountService;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordAccount;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditService;
import com.github.guoyyit.accountpasswordresetjava.config.SecurityProperties;
import com.github.guoyyit.accountpasswordresetjava.security.TokenSupport;
import com.github.guoyyit.accountpasswordresetjava.session.SessionService;

@Service
public class ResetService {

    public static final String TOKEN_PREFIX = "rst_";
    private static final int TOKEN_BODY_LENGTH = 43;

    private final AccountRepository accountRepository;
    private final ResetCredentialRepository credentialRepository;
    private final AccountService accountService;
    private final SessionService sessionService;
    private final TokenSupport tokenSupport;
    private final ResetDelivery resetDelivery;
    private final SecurityProperties properties;
    private final AuditService auditService;

    public ResetService(AccountRepository accountRepository,
                        ResetCredentialRepository credentialRepository,
                        AccountService accountService,
                        SessionService sessionService,
                        TokenSupport tokenSupport,
                        ResetDelivery resetDelivery,
                        SecurityProperties properties,
                        AuditService auditService) {
        this.accountRepository = accountRepository;
        this.credentialRepository = credentialRepository;
        this.accountService = accountService;
        this.sessionService = sessionService;
        this.tokenSupport = tokenSupport;
        this.resetDelivery = resetDelivery;
        this.properties = properties;
        this.auditService = auditService;
    }

    @Transactional
    public void requestReset(String username) {
        String normalized = AccountService.normalizeUsername(username);
        Optional<PasswordAccount> locked = accountRepository.findByUsernameForUpdate(normalized);
        if (locked.isEmpty()) {
            tokenSupport.hashOf(tokenSupport.newToken(TOKEN_PREFIX));
            auditService.record("RESET_REQUESTED", null,
                    "username=" + normalized + " outcome=accepted");
            return;
        }
        PasswordAccount account = locked.get();
        Instant now = Instant.now();
        Instant windowStart = now.minus(properties.getResetRateLimitWindow());
        long recent = credentialRepository.countByAccountIdAndCreatedAtAfter(
                account.getId(), windowStart);
        if (recent >= properties.getResetRateLimitMax()) {
            auditService.record("RESET_REQUEST_RATE_LIMITED", account.getId(),
                    "username=" + normalized + " recent=" + recent);
            return;
        }
        List<ResetCredential> active = credentialRepository
                .findByAccountIdAndUsedAtIsNullAndSupersededAtIsNull(account.getId());
        for (ResetCredential credential : active) {
            credential.setSupersededAt(now);
            credentialRepository.save(credential);
        }
        String rawToken = tokenSupport.newToken(TOKEN_PREFIX);
        ResetCredential credential = new ResetCredential(
                account.getId(),
                tokenSupport.hashOf(rawToken),
                now,
                now.plus(properties.getResetTokenTtl()));
        credentialRepository.save(credential);
        auditService.record("RESET_CREDENTIAL_ISSUED", account.getId(),
                "credentialId=" + credential.getId() + " superseded=" + active.size());
        resetDelivery.deliver(account.getUsername(), rawToken);
    }

    @Transactional(readOnly = true)
    public void verify(String rawToken) {
        ResetCredential credential = requireUsable(rawToken, "RESET_VERIFY");
        auditService.record("RESET_VERIFY_SUCCEEDED", credential.getAccountId(),
                "credentialId=" + credential.getId());
    }

    @Transactional
    public void confirmReset(String rawToken, String newPassword) {
        ResetCredential credential = requireUsableLocked(rawToken);
        PasswordAccount account = accountRepository.findById(credential.getAccountId())
                .orElseThrow(() -> new IllegalStateException("account missing for credential"));
        accountService.resetPassword(account, newPassword);
        sessionService.revokeAllForAccount(account.getId());
        credential.setUsedAt(Instant.now());
        credentialRepository.save(credential);
        auditService.record("RESET_CONFIRM_SUCCEEDED", account.getId(),
                "credentialId=" + credential.getId());
    }

    private ResetCredential requireUsable(String rawToken, String auditPrefix) {
        String tokenHash = parseAndHash(rawToken, auditPrefix);
        Optional<ResetCredential> found = credentialRepository.findByTokenHash(tokenHash);
        if (found.isEmpty()) {
            auditService.record(auditPrefix + "_FAILED", null, "reason=invalid_credential");
            throw new InvalidCredentialException("invalid_credential");
        }
        if (!found.get().isUsableAt(Instant.now())) {
            auditService.record(auditPrefix + "_FAILED", found.get().getAccountId(),
                    "reason=invalid_credential credentialId=" + found.get().getId());
            throw new InvalidCredentialException("invalid_credential");
        }
        return found.get();
    }

    private ResetCredential requireUsableLocked(String rawToken) {
        String tokenHash = parseAndHash(rawToken, "RESET_CONFIRM");
        Optional<ResetCredential> found = credentialRepository.findByTokenHashForUpdate(tokenHash);
        if (found.isEmpty()) {
            auditService.record("RESET_CONFIRM_FAILED", null, "reason=invalid_credential");
            throw new InvalidCredentialException("invalid_credential");
        }
        if (!found.get().isUsableAt(Instant.now())) {
            auditService.record("RESET_CONFIRM_FAILED", found.get().getAccountId(),
                    "reason=invalid_credential credentialId=" + found.get().getId());
            throw new InvalidCredentialException("invalid_credential");
        }
        return found.get();
    }

    private String parseAndHash(String rawToken, String auditPrefix) {
        if (!isWellFormed(rawToken)) {
            auditService.record(auditPrefix + "_FAILED", null, "reason=malformed_token");
            throw new InvalidCredentialException("invalid_credential");
        }
        return tokenSupport.hashOf(rawToken);
    }

    private boolean isWellFormed(String rawToken) {
        if (rawToken == null || rawToken.length() != TOKEN_PREFIX.length() + TOKEN_BODY_LENGTH
                || !rawToken.startsWith(TOKEN_PREFIX)) {
            return false;
        }
        for (int i = TOKEN_PREFIX.length(); i < rawToken.length(); i++) {
            char c = rawToken.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }
}
