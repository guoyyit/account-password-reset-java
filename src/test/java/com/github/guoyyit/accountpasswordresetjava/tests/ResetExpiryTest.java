package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.delivery.LocalDeliveryService;
import com.github.guoyyit.accountpasswordresetjava.web.dto.ConfirmResetRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MessageResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RegisterRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RequestResetRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.VerifyResetRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 凭据过期：TTL 设为 0，签发的凭据立即过期，校验与确认统一拒绝。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:resetexpiry;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/resetexpiry",
        "app.reset-token-ttl=PT0S"
})
class ResetExpiryTest {

    private static final Pattern CODE_PATTERN = Pattern.compile("code: (\\d{6})");

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private LocalDeliveryService deliveryService;

    @Test
    void expiredCredentialIsRejectedUniformly() {
        rest.postForEntity("/api/auth/register", new RegisterRequest("judy", "OldPassw0rd"),
                MessageResponse.class);
        rest.postForEntity("/api/reset/request", new RequestResetRequest("judy"), MessageResponse.class);

        List<String> outbox = deliveryService.outboxFor("judy");
        assertThat(outbox).isNotEmpty();
        Matcher matcher = CODE_PATTERN.matcher(outbox.get(outbox.size() - 1));
        assertThat(matcher.find()).isTrue();
        String code = matcher.group(1);

        ResponseEntity<MessageResponse> verify = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("judy", code), MessageResponse.class);
        assertThat(verify.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(verify.getBody().message()).isEqualTo("invalid or expired reset credential");

        ResponseEntity<MessageResponse> confirm = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("judy", code, "N3wPassw0rd"), MessageResponse.class);
        assertThat(confirm.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(confirm.getBody().message()).isEqualTo("invalid or expired reset credential");
    }
}
