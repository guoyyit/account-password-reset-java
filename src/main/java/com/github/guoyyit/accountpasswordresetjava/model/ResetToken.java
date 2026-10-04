package com.github.guoyyit.accountpasswordresetjava.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "reset_tokens", indexes = @Index(name = "idx_reset_token_hash", columnList = "tokenHash", unique = true))
public class ResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String tokenHash;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id")
    private Account account;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiresAt;

    private Instant usedAt;

    private Instant invalidatedAt;

    @Column(nullable = false)
    private int failedAttempts;

    protected ResetToken() {
    }

    public ResetToken(String tokenHash, Account account, Instant createdAt, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.account = account;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.failedAttempts = 0;
    }

    public Long getId() {
        return id;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Account getAccount() {
        return account;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public Instant getInvalidatedAt() {
        return invalidatedAt;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void markUsed(Instant when) {
        this.usedAt = when;
    }

    public void invalidate(Instant when) {
        this.invalidatedAt = when;
    }

    public void incrementFailedAttempts() {
        this.failedAttempts++;
    }

    public boolean isUsable(Instant now) {
        return usedAt == null && invalidatedAt == null && expiresAt.isAfter(now);
    }
}
