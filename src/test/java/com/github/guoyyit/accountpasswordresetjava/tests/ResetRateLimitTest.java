package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.repository.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MessageResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RegisterRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RequestResetRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 申请频率限制：同一账户窗口内最多 3 次，第 4 次拒绝；对不存在账户同样适用。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:resetratelimit;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/resetratelimit",
        "app.reset-request-max=3",
        "app.reset-request-window=PT10M"
})
class ResetRateLimitTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Test
    void requestsBeyondLimitAreRejected() {
        rest.postForEntity("/api/auth/register", new RegisterRequest("mallory", "Str0ngPass"),
                MessageResponse.class);

        for (int i = 0; i < 3; i++) {
            ResponseEntity<MessageResponse> ok = rest.postForEntity("/api/reset/request",
                    new RequestResetRequest("mallory"), MessageResponse.class);
            assertThat(ok.getStatusCode()).isEqualTo(HttpStatus.OK);
        }
        ResponseEntity<MessageResponse> limited = rest.postForEntity("/api/reset/request",
                new RequestResetRequest("mallory"), MessageResponse.class);
        assertThat(limited.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

        assertThat(auditEventRepository.findByType(AuditEventType.RESET_REQUEST_RATE_LIMITED))
                .isNotEmpty();
    }

    @Test
    void limitAppliesToUnknownAccountsToo() {
        for (int i = 0; i < 3; i++) {
            rest.postForEntity("/api/reset/request", new RequestResetRequest("ghost"),
                    MessageResponse.class);
        }
        ResponseEntity<MessageResponse> limited = rest.postForEntity("/api/reset/request",
                new RequestResetRequest("ghost"), MessageResponse.class);
        assertThat(limited.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }
}
