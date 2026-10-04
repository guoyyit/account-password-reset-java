package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.delivery.LocalDeliveryService;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.repository.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.web.dto.ConfirmResetRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.LoginRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.LoginResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MeResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MessageResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RegisterRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RequestResetRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.VerifyResetRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:resetflow;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/resetflow"
})
class ResetFlowTest {

    private static final Pattern CODE_PATTERN = Pattern.compile("code: (\\d{6})");

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private LocalDeliveryService deliveryService;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Test
    void fullResetFlowRevokesExistingSessionsAndOldPassword() {
        register("dave", "OldPassw0rd");
        String sessionToken = login("dave", "OldPassw0rd");

        rest.postForEntity("/api/reset/request", new RequestResetRequest("dave"), MessageResponse.class);
        String code = latestCode("dave");

        ResponseEntity<MessageResponse> verify = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("dave", code), MessageResponse.class);
        assertThat(verify.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<MessageResponse> confirm = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("dave", code, "N3wPassw0rd"), MessageResponse.class);
        assertThat(confirm.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<MeResponse> me = rest.exchange("/api/auth/me", HttpMethod.GET,
                bearer(sessionToken), MeResponse.class);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<MessageResponse> oldLogin = rest.postForEntity("/api/auth/login",
                new LoginRequest("dave", "OldPassw0rd"), MessageResponse.class);
        assertThat(oldLogin.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<LoginResponse> newLogin = rest.postForEntity("/api/auth/login",
                new LoginRequest("dave", "N3wPassw0rd"), LoginResponse.class);
        assertThat(newLogin.getStatusCode()).isEqualTo(HttpStatus.OK);

        List<AuditEventType> events = auditEventRepository
                .findByUsernameOrderByCreatedAtAsc("dave").stream().map(AuditEvent::getType).toList();
        assertThat(events).contains(AuditEventType.RESET_REQUESTED,
                AuditEventType.RESET_VERIFY_SUCCESS,
                AuditEventType.SESSIONS_REVOKED_ALL,
                AuditEventType.RESET_CONFIRM_SUCCESS);
    }

    @Test
    void usedCredentialCannotBeReplayed() {
        register("erin", "OldPassw0rd");
        rest.postForEntity("/api/reset/request", new RequestResetRequest("erin"), MessageResponse.class);
        String code = latestCode("erin");

        ResponseEntity<MessageResponse> confirm = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("erin", code, "N3wPassw0rd"), MessageResponse.class);
        assertThat(confirm.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<MessageResponse> replayConfirm = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("erin", code, "An0therPass1"), MessageResponse.class);
        assertThat(replayConfirm.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(replayConfirm.getBody().message()).isEqualTo("invalid or expired reset credential");

        ResponseEntity<MessageResponse> replayVerify = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("erin", code), MessageResponse.class);
        assertThat(replayVerify.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(replayVerify.getBody().message()).isEqualTo("invalid or expired reset credential");
    }

    @Test
    void malformedAndWrongCredentialsGetUniformRejection() {
        register("frank", "OldPassw0rd");
        rest.postForEntity("/api/reset/request", new RequestResetRequest("frank"), MessageResponse.class);

        for (String malformed : new String[]{"abc", "12345", "1234567", "12 456", ""}) {
            ResponseEntity<MessageResponse> response = rest.postForEntity("/api/reset/verify",
                    new VerifyResetRequest("frank", malformed), MessageResponse.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().message()).isEqualTo("invalid or expired reset credential");
        }

        ResponseEntity<MessageResponse> wrongCode = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("frank", "000000"), MessageResponse.class);
        assertThat(wrongCode.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(wrongCode.getBody().message()).isEqualTo("invalid or expired reset credential");
    }

    @Test
    void tooManyWrongAttemptsInvalidateCredential() {
        register("grace", "OldPassw0rd");
        rest.postForEntity("/api/reset/request", new RequestResetRequest("grace"), MessageResponse.class);
        String code = latestCode("grace");

        for (int i = 0; i < 5; i++) {
            rest.postForEntity("/api/reset/verify",
                    new VerifyResetRequest("grace", "00000" + i), MessageResponse.class);
        }

        ResponseEntity<MessageResponse> verify = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("grace", code), MessageResponse.class);
        assertThat(verify.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(verify.getBody().message()).isEqualTo("invalid or expired reset credential");
    }

    @Test
    void newPasswordMustSatisfyPolicyAndDifferFromHistory() {
        register("heidi", "FirstPass1");
        rest.postForEntity("/api/reset/request", new RequestResetRequest("heidi"), MessageResponse.class);
        String code = latestCode("heidi");

        ResponseEntity<MessageResponse> weak = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("heidi", code, "weak"), MessageResponse.class);
        assertThat(weak.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<MessageResponse> reused = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("heidi", code, "FirstPass1"), MessageResponse.class);
        assertThat(reused.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<MessageResponse> ok = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("heidi", code, "SecondPass2"), MessageResponse.class);
        assertThat(ok.getStatusCode()).isEqualTo(HttpStatus.OK);

        rest.postForEntity("/api/reset/request", new RequestResetRequest("heidi"), MessageResponse.class);
        String code2 = latestCode("heidi");
        ResponseEntity<MessageResponse> reuseOlder = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("heidi", code2, "FirstPass1"), MessageResponse.class);
        assertThat(reuseOlder.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void newRequestInvalidatesPreviousCredential() {
        register("ivan", "OldPassw0rd");
        rest.postForEntity("/api/reset/request", new RequestResetRequest("ivan"), MessageResponse.class);
        String firstCode = latestCode("ivan");
        rest.postForEntity("/api/reset/request", new RequestResetRequest("ivan"), MessageResponse.class);
        String secondCode = latestCode("ivan");
        assertThat(secondCode).isNotEqualTo(firstCode);

        ResponseEntity<MessageResponse> oldCode = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("ivan", firstCode), MessageResponse.class);
        assertThat(oldCode.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<MessageResponse> newCode = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("ivan", secondCode), MessageResponse.class);
        assertThat(newCode.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private void register(String username, String password) {
        rest.postForEntity("/api/auth/register", new RegisterRequest(username, password), MessageResponse.class);
    }

    private String login(String username, String password) {
        ResponseEntity<LoginResponse> login = rest.postForEntity("/api/auth/login",
                new LoginRequest(username, password), LoginResponse.class);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        return login.getBody().sessionToken();
    }

    private String latestCode(String username) {
        List<String> outbox = deliveryService.outboxFor(username);
        assertThat(outbox).isNotEmpty();
        Matcher matcher = CODE_PATTERN.matcher(outbox.get(outbox.size() - 1));
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private static HttpEntity<Void> bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        return new HttpEntity<>(headers);
    }
}
