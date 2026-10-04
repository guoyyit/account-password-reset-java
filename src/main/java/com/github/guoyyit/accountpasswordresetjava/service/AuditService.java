package com.github.guoyyit.accountpasswordresetjava.service;

import com.github.guoyyit.accountpasswordresetjava.model.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.repository.AuditEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuditService {

    private final AuditEventRepository auditEventRepository;

    public AuditService(AuditEventRepository auditEventRepository) {
        this.auditEventRepository = auditEventRepository;
    }

    /**
     * 审计记录独立于业务事务提交：即使业务操作失败回滚，失败事件也不丢失。
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType type, Long accountId, String username, String detail) {
        String safeDetail = detail == null ? "" : detail;
        if (safeDetail.length() > 1000) {
            safeDetail = safeDetail.substring(0, 1000);
        }
        auditEventRepository.save(new AuditEvent(type, accountId, username, safeDetail, Instant.now()));
    }
}
