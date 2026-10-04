package com.github.guoyyit.accountpasswordresetjava.audit;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findByEventType(String eventType);

    List<AuditEvent> findByAccountId(Long accountId);
}
