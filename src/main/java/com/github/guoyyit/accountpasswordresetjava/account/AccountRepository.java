package com.github.guoyyit.accountpasswordresetjava.account;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface AccountRepository extends JpaRepository<PasswordAccount, Long> {

    Optional<PasswordAccount> findByUsername(String username);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from PasswordAccount a where a.username = :username")
    Optional<PasswordAccount> findByUsernameForUpdate(@Param("username") String username);
}
