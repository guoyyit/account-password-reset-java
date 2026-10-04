package com.github.guoyyit.accountpasswordresetjava.service;

import com.github.guoyyit.accountpasswordresetjava.model.Account;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.model.PasswordHistoryEntry;
import com.github.guoyyit.accountpasswordresetjava.repository.AccountRepository;
import com.github.guoyyit.accountpasswordresetjava.repository.PasswordHistoryRepository;
import com.github.guoyyit.accountpasswordresetjava.web.ApiException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class AccountService {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{3,32}$");

    private final AccountRepository accountRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordService passwordService;
    private final SessionService sessionService;
    private final AuditService auditService;

    public AccountService(AccountRepository accountRepository,
                          PasswordHistoryRepository passwordHistoryRepository,
                          PasswordService passwordService,
                          SessionService sessionService,
                          AuditService auditService) {
        this.accountRepository = accountRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.passwordService = passwordService;
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    @Transactional
    public Account register(String username, String password) {
        String normalized = normalizeUsername(username);
        passwordService.assertStrength(password);
        if (accountRepository.findByUsername(normalized).isPresent()) {
            throw ApiException.conflict("username already registered");
        }
        String hash = passwordService.hash(password);
        Account account = accountRepository.save(new Account(normalized, hash, Instant.now()));
        passwordHistoryRepository.save(new PasswordHistoryEntry(account, hash, Instant.now()));
        auditService.record(AuditEventType.ACCOUNT_REGISTERED, account.getId(), normalized, "account registered");
        return account;
    }

    @Transactional
    public SessionService.IssuedSession login(String username, String password) {
        String normalized = normalizeUsername(username);
        Account account = accountRepository.findByUsername(normalized).orElse(null);
        if (account == null || !passwordService.matches(password, account.getPasswordHash())) {
            auditService.record(AuditEventType.LOGIN_FAILURE,
                    account == null ? null : account.getId(), normalized, "invalid credentials");
            throw ApiException.unauthorized("invalid username or password");
        }
        SessionService.IssuedSession session = sessionService.issue(account);
        auditService.record(AuditEventType.LOGIN_SUCCESS, account.getId(), normalized, "login success");
        return session;
    }

    public boolean isPasswordReused(Account account, String rawPassword) {
        List<PasswordHistoryEntry> history = passwordHistoryRepository.findByAccountId(account.getId());
        for (PasswordHistoryEntry entry : history) {
            if (passwordService.matches(rawPassword, entry.getPasswordHash())) {
                return true;
            }
        }
        return false;
    }

    static String normalizeUsername(String username) {
        if (username == null) {
            throw ApiException.badRequest("username is required");
        }
        String normalized = username.trim().toLowerCase();
        if (!USERNAME_PATTERN.matcher(normalized).matches()) {
            throw ApiException.badRequest("username must be 3-32 chars of [a-zA-Z0-9_.-]");
        }
        return normalized;
    }
}
