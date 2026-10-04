package com.github.guoyyit.accountpasswordresetjava.audit;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_event", indexes = @Index(columnList = "accountId"))
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant occurredAt;

    @Column(nullable = false)
    private String eventType;

    private Long accountId;

    @Column(length = 1024)
    private String detail;

    protected AuditEvent() {
    }

    public AuditEvent(Instant occurredAt, String eventType, Long accountId, String detail) {
        this.occurredAt = occurredAt;
        this.eventType = eventType;
        this.accountId = accountId;
        this.detail = detail;
    }

    public Long getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getEventType() {
        return eventType;
    }

    public Long getAccountId() {
        return accountId;
    }

    public String getDetail() {
        return detail;
    }
}
