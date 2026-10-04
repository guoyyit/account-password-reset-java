package com.github.guoyyit.accountpasswordresetjava.account;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistoryEntry, Long> {

    List<PasswordHistoryEntry> findByAccountId(Long accountId);
}
