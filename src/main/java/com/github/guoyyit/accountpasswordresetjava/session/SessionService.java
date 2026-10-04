package com.github.guoyyit.accountpasswordresetjava.session;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.github.guoyyit.accountpasswordresetjava.account.PasswordAccount;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditService;
import com.github.guoyyit.accountpasswordresetjava.config.SecurityProperties;
import com.github.guoyyit.accountpasswordresetjava.security.TokenSupport;

@Service
public class SessionService {

    public record IssuedSession(String token, String sessionId, Instant expiresAt) {
    }

    private final SessionRepository sessionRepository;
    private final TokenSupport tokenSupport;
    private final SecurityProperties properties;
    private final AuditService auditService;

    public SessionService(SessionRepository sessionRepository,
                          TokenSupport tokenSupport,
                          SecurityProperties properties,
                          AuditService auditService) {
        this.sessionRepository = sessionRepository;
        this.tokenSupport = tokenSupport;
        this.properties = properties;
        this.auditService = auditService;
    }

    @Transactional
    public IssuedSession issue(PasswordAccount account) {
        String rawToken = tokenSupport.newToken("ses_");
        Instant now = Instant.now();
        LoginSession session = new LoginSession(
                UUID.randomUUID().toString(),
                account.getId(),
                tokenSupport.hashOf(rawToken),
                now,
                now.plus(properties.getSessionTtl()));
        sessionRepository.save(session);
        auditService.record("SESSION_ISSUED", account.getId(),
                "sessionId=" + session.getSessionPublicId());
        return new IssuedSession(rawToken, session.getSessionPublicId(), session.getExpiresAt());
    }

    @Transactional(readOnly = true)
    public Optional<LoginSession> authenticate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        Optional<LoginSession> session = sessionRepository.findByTokenHash(
                tokenSupport.hashOf(rawToken));
        if (session.isEmpty() || !session.get().isActiveAt(Instant.now())) {
            return Optional.empty();
        }
        return session;
    }

    @Transactional
    public void revoke(LoginSession session) {
        if (session.getRevokedAt() == null) {
            session.setRevokedAt(Instant.now());
            sessionRepository.save(session);
            auditService.record("SESSION_REVOKED", session.getAccountId(),
                    "sessionId=" + session.getSessionPublicId());
        }
    }

    @Transactional
    public void revokeAllForAccount(Long accountId) {
        List<LoginSession> active = sessionRepository.findByAccountIdAndRevokedAtIsNull(accountId);
        Instant now = Instant.now();
        for (LoginSession session : active) {
            session.setRevokedAt(now);
            sessionRepository.save(session);
        }
        auditService.record("SESSIONS_REVOKED_ALL", accountId, "count=" + active.size());
    }
}
