package com.github.guoyyit.accountpasswordresetjava.service;

import com.github.guoyyit.accountpasswordresetjava.config.AppProperties;
import com.github.guoyyit.accountpasswordresetjava.model.ResetToken;
import com.github.guoyyit.accountpasswordresetjava.repository.ResetTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class ResetAttemptService {

    private final ResetTokenRepository resetTokenRepository;
    private final AppProperties properties;

    public ResetAttemptService(ResetTokenRepository resetTokenRepository, AppProperties properties) {
        this.resetTokenRepository = resetTokenRepository;
        this.properties = properties;
    }

    /**
     * 将一次失败的校验/确认计到该账户当前可用凭据上，达到上限即作废。
     * 独立事务提交：调用方随后抛出异常回滚业务事务时，失败计数仍然保留。
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registerFailedAttempt(Long accountId, Instant now) {
        List<ResetToken> tokens = resetTokenRepository.findByAccountId(accountId);
        for (ResetToken token : tokens) {
            if (token.isUsable(now)) {
                token.incrementFailedAttempts();
                if (token.getFailedAttempts() >= properties.getResetMaxAttempts()) {
                    token.invalidate(now);
                }
            }
        }
    }
}
