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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 账户枚举探测：对存在与不存在的账户发起申请，响应必须不可区分。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:enumeration;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/enumeration"
})
class EnumerationTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private LocalDeliveryService deliveryService;

    @Test
    void requestResponseIsIndistinguishableForUnknownAccount() {
        rest.postForEntity("/api/auth/register", new RegisterRequest("knownuser", "Str0ngPass"),
                MessageResponse.class);

        ResponseEntity<MessageResponse> existing = rest.postForEntity("/api/reset/request",
                new RequestResetRequest("knownuser"), MessageResponse.class);
        ResponseEntity<MessageResponse> unknown = rest.postForEntity("/api/reset/request",
                new RequestResetRequest("ghostuser"), MessageResponse.class);

        assertThat(unknown.getStatusCode()).isEqualTo(existing.getStatusCode());
        assertThat(unknown.getBody().message()).isEqualTo(existing.getBody().message());

        assertThat(deliveryService.outboxFor("knownuser")).isNotEmpty();
        assertThat(deliveryService.outboxFor("ghostuser")).isEmpty();
    }

    @Test
    void verifyAndConfirmForUnknownAccountGetUniformRejection() {
        ResponseEntity<MessageResponse> verify = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("ghostuser", "123456"), MessageResponse.class);
        assertThat(verify.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(verify.getBody().message()).isEqualTo("invalid or expired reset credential");

        ResponseEntity<MessageResponse> confirm = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("ghostuser", "123456", "N3wPassw0rd"), MessageResponse.class);
        assertThat(confirm.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(confirm.getBody().message()).isEqualTo("invalid or expired reset credential");
    }
}
