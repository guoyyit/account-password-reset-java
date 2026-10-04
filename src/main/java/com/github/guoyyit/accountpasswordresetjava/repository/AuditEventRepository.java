package com.github.guoyyit.accountpasswordresetjava.repository;

import com.github.guoyyit.accountpasswordresetjava.model.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findByUsernameOrderByCreatedAtAsc(String username);

    List<AuditEvent> findByType(AuditEventType type);
}
