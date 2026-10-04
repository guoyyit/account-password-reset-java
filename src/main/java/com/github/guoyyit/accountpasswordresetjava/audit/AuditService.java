package com.github.guoyyit.accountpasswordresetjava.audit;

import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {

    private final AuditEventRepository repository;

    public AuditService(AuditEventRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void record(String eventType, Long accountId, String detail) {
        repository.save(new AuditEvent(Instant.now(), eventType, accountId, detail));
    }
}
