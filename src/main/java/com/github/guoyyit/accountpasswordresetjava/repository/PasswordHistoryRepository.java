package com.github.guoyyit.accountpasswordresetjava.repository;

import com.github.guoyyit.accountpasswordresetjava.model.PasswordHistoryEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistoryEntry, Long> {

    List<PasswordHistoryEntry> findByAccountId(Long accountId);
}
