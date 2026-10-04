package com.github.guoyyit.accountpasswordresetjava.account;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name = "password_history", indexes = @Index(columnList = "accountId"))
public class PasswordHistoryEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long accountId;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private Instant recordedAt;

    protected PasswordHistoryEntry() {
    }

    public PasswordHistoryEntry(Long accountId, String passwordHash, Instant recordedAt) {
        this.accountId = accountId;
        this.passwordHash = passwordHash;
        this.recordedAt = recordedAt;
    }

    public Long getId() {
        return id;
    }

    public Long getAccountId() {
        return accountId;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Instant getRecordedAt() {
        return recordedAt;
    }
}
