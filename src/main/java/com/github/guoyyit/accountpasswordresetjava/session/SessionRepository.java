package com.github.guoyyit.accountpasswordresetjava.session;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<LoginSession, Long> {

    Optional<LoginSession> findByTokenHash(String tokenHash);

    Optional<LoginSession> findBySessionPublicId(String sessionPublicId);

    List<LoginSession> findByAccountIdAndRevokedAtIsNull(Long accountId);
}
