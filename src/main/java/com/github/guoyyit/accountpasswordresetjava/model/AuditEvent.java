package com.github.guoyyit.accountpasswordresetjava.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType type;

    private Long accountId;

    private String username;

    @Column(nullable = false, length = 1024)
    private String detail;

    @Column(nullable = false)
    private Instant createdAt;

    protected AuditEvent() {
    }

    public AuditEvent(AuditEventType type, Long accountId, String username, String detail, Instant createdAt) {
        this.type = type;
        this.accountId = accountId;
        this.username = username;
        this.detail = detail;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public AuditEventType getType() {
        return type;
    }

    public Long getAccountId() {
        return accountId;
    }

    public String getUsername() {
        return username;
    }

    public String getDetail() {
        return detail;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
