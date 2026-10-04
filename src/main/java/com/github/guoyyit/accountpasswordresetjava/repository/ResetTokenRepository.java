package com.github.guoyyit.accountpasswordresetjava.repository;

import com.github.guoyyit.accountpasswordresetjava.model.ResetToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ResetTokenRepository extends JpaRepository<ResetToken, Long> {

    Optional<ResetToken> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from ResetToken t where t.tokenHash = :tokenHash")
    Optional<ResetToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    List<ResetToken> findByAccountId(Long accountId);
}
