package com.github.guoyyit.accountpasswordresetjava.repository;

import com.github.guoyyit.accountpasswordresetjava.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, Long> {

    Optional<Session> findByTokenHash(String tokenHash);

    List<Session> findByAccountId(Long accountId);
}
