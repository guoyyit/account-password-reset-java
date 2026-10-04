package com.github.guoyyit.accountpasswordresetjava.service;

import com.github.guoyyit.accountpasswordresetjava.config.AppProperties;
import com.github.guoyyit.accountpasswordresetjava.model.Account;
import com.github.guoyyit.accountpasswordresetjava.model.Session;
import com.github.guoyyit.accountpasswordresetjava.repository.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class SessionService {

    public record IssuedSession(String token, Instant expiresAt) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SessionRepository sessionRepository;
    private final TokenDigestService tokenDigestService;
    private final AppProperties properties;

    public SessionService(SessionRepository sessionRepository,
                          TokenDigestService tokenDigestService,
                          AppProperties properties) {
        this.sessionRepository = sessionRepository;
        this.tokenDigestService = tokenDigestService;
        this.properties = properties;
    }

    @Transactional
    public IssuedSession issue(Account account) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.getSessionTtl());
        sessionRepository.save(new Session(tokenDigestService.digest(rawToken), account, now, expiresAt));
        return new IssuedSession(rawToken, expiresAt);
    }

    @Transactional(readOnly = true)
    public Optional<Session> resolve(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        return sessionRepository.findByTokenHash(tokenDigestService.digest(rawToken))
                .filter(session -> session.isActive(Instant.now()));
    }

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        sessionRepository.findByTokenHash(tokenDigestService.digest(rawToken))
                .ifPresent(session -> session.revoke(Instant.now()));
    }

    @Transactional
    public int revokeAllForAccount(Long accountId) {
        List<Session> sessions = sessionRepository.findByAccountId(accountId);
        Instant now = Instant.now();
        int count = 0;
        for (Session session : sessions) {
            if (session.getRevokedAt() == null) {
                session.revoke(now);
                count++;
            }
        }
        return count;
    }
}
