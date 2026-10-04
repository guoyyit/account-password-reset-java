package com.github.guoyyit.accountpasswordresetjava.account;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.github.guoyyit.accountpasswordresetjava.audit.AuditService;
import com.github.guoyyit.accountpasswordresetjava.security.PasswordHasher;
import com.github.guoyyit.accountpasswordresetjava.security.PasswordPolicy;

@Service
public class AccountService {

    private static final int MAX_USERNAME_LENGTH = 64;

    private final AccountRepository accountRepository;
    private final PasswordHistoryRepository historyRepository;
    private final PasswordHasher passwordHasher;
    private final PasswordPolicy passwordPolicy;
    private final AuditService auditService;

    private volatile String dummyHash;

    public AccountService(AccountRepository accountRepository,
                          PasswordHistoryRepository historyRepository,
                          PasswordHasher passwordHasher,
                          PasswordPolicy passwordPolicy,
                          AuditService auditService) {
        this.accountRepository = accountRepository;
        this.historyRepository = historyRepository;
        this.passwordHasher = passwordHasher;
        this.passwordPolicy = passwordPolicy;
        this.auditService = auditService;
    }

    @Transactional
    public PasswordAccount register(String username, String rawPassword) {
        String normalized = normalizeUsername(username);
        String violation = passwordPolicy.checkViolation(normalized, rawPassword);
        if (violation != null) {
            auditService.record("REGISTER_REJECTED", null,
                    "username=" + normalized + " reason=" + violation);
            throw new PasswordPolicyException(violation);
        }
        if (accountRepository.findByUsername(normalized).isPresent()) {
            auditService.record("REGISTER_REJECTED", null,
                    "username=" + normalized + " reason=username_unavailable");
            throw new UsernameUnavailableException("username_unavailable");
        }
        String hash = passwordHasher.hash(rawPassword);
        PasswordAccount account = accountRepository.save(
                new PasswordAccount(normalized, hash, Instant.now()));
        historyRepository.save(new PasswordHistoryEntry(account.getId(), hash, Instant.now()));
        auditService.record("ACCOUNT_REGISTERED", account.getId(), "username=" + normalized);
        return account;
    }

    @Transactional(readOnly = true)
    public Optional<PasswordAccount> authenticate(String username, String rawPassword) {
        String normalized = normalizeUsername(username);
        Optional<PasswordAccount> account = accountRepository.findByUsername(normalized);
        if (account.isEmpty()) {
            passwordHasher.matches(rawPassword == null ? "" : rawPassword, dummyHash());
            auditService.record("LOGIN_FAILED", null, "username=" + normalized);
            return Optional.empty();
        }
        if (!passwordHasher.matches(rawPassword == null ? "" : rawPassword,
                account.get().getPasswordHash())) {
            auditService.record("LOGIN_FAILED", account.get().getId(), "username=" + normalized);
            return Optional.empty();
        }
        auditService.record("LOGIN_SUCCEEDED", account.get().getId(), "username=" + normalized);
        return account;
    }

    @Transactional(readOnly = true)
    public Optional<PasswordAccount> findById(Long accountId) {
        return accountRepository.findById(accountId);
    }

    @Transactional
    public void resetPassword(PasswordAccount account, String rawPassword) {
        String violation = passwordPolicy.checkViolation(account.getUsername(), rawPassword);
        if (violation != null) {
            auditService.record("PASSWORD_RESET_REJECTED", account.getId(), "reason=" + violation);
            throw new PasswordPolicyException(violation);
        }
        if (passwordHasher.matches(rawPassword, account.getPasswordHash())) {
            auditService.record("PASSWORD_RESET_REJECTED", account.getId(), "reason=password_reused");
            throw new PasswordPolicyException("password_reused");
        }
        List<PasswordHistoryEntry> history = historyRepository.findByAccountId(account.getId());
        for (PasswordHistoryEntry entry : history) {
            if (passwordHasher.matches(rawPassword, entry.getPasswordHash())) {
                auditService.record("PASSWORD_RESET_REJECTED", account.getId(),
                        "reason=password_reused");
                throw new PasswordPolicyException("password_reused");
            }
        }
        String newHash = passwordHasher.hash(rawPassword);
        account.setPasswordHash(newHash);
        accountRepository.save(account);
        historyRepository.save(new PasswordHistoryEntry(account.getId(), newHash, Instant.now()));
        auditService.record("PASSWORD_RESET_SUCCEEDED", account.getId(), null);
    }

    public static String normalizeUsername(String username) {
        if (username == null) {
            return "";
        }
        String normalized = username.trim().toLowerCase();
        if (normalized.length() > MAX_USERNAME_LENGTH) {
            return normalized.substring(0, MAX_USERNAME_LENGTH);
        }
        return normalized;
    }

    private String dummyHash() {
        if (dummyHash == null) {
            synchronized (this) {
                if (dummyHash == null) {
                    dummyHash = passwordHasher.hash("dummy-password-for-timing");
                }
            }
        }
        return dummyHash;
    }
}
