package com.github.guoyyit.accountpasswordresetjava.reset;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface ResetCredentialRepository extends JpaRepository<ResetCredential, Long> {

    Optional<ResetCredential> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from ResetCredential c where c.tokenHash = :tokenHash")
    Optional<ResetCredential> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    List<ResetCredential> findByAccountIdAndUsedAtIsNullAndSupersededAtIsNull(Long accountId);

    long countByAccountIdAndCreatedAtAfter(Long accountId, Instant after);
}
