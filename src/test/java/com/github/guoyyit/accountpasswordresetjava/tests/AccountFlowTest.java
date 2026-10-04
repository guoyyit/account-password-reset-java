package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.model.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.repository.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.web.dto.LoginRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.LoginResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MeResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MessageResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RegisterRequest;
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

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:accountflow;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/accountflow"
})
class AccountFlowTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Test
    void registerLoginAndSessionLifecycle() {
        ResponseEntity<MessageResponse> registered = rest.postForEntity("/api/auth/register",
                new RegisterRequest("alice", "Passw0rd!x"), MessageResponse.class);
        assertThat(registered.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<LoginResponse> login = rest.postForEntity("/api/auth/login",
                new LoginRequest("alice", "Passw0rd!x"), LoginResponse.class);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = login.getBody().sessionToken();
        assertThat(token).isNotBlank();

        ResponseEntity<MeResponse> me = rest.exchange("/api/auth/me", HttpMethod.GET,
                bearer(token), MeResponse.class);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody().username()).isEqualTo("alice");

        ResponseEntity<MessageResponse> logout = rest.exchange("/api/auth/logout", HttpMethod.POST,
                bearer(token), MessageResponse.class);
        assertThat(logout.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<MeResponse> meAfterLogout = rest.exchange("/api/auth/me", HttpMethod.GET,
                bearer(token), MeResponse.class);
        assertThat(meAfterLogout.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        List<AuditEventType> eventTypes = auditEventRepository
                .findByUsernameOrderByCreatedAtAsc("alice").stream().map(AuditEvent::getType).toList();
        assertThat(eventTypes).contains(AuditEventType.ACCOUNT_REGISTERED,
                AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGOUT);
    }

    @Test
    void registerRejectsWeakPasswordAndDuplicateUsername() {
        ResponseEntity<MessageResponse> weak = rest.postForEntity("/api/auth/register",
                new RegisterRequest("bob", "short"), MessageResponse.class);
        assertThat(weak.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<MessageResponse> noDigit = rest.postForEntity("/api/auth/register",
                new RegisterRequest("bob", "onlyletters"), MessageResponse.class);
        assertThat(noDigit.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        rest.postForEntity("/api/auth/register", new RegisterRequest("bob", "Str0ngPass"), MessageResponse.class);
        ResponseEntity<MessageResponse> duplicate = rest.postForEntity("/api/auth/register",
                new RegisterRequest("bob", "An0therPass"), MessageResponse.class);
        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void loginRejectsWrongPasswordAndUnknownUser() {
        rest.postForEntity("/api/auth/register", new RegisterRequest("carol", "Str0ngPass"), MessageResponse.class);

        ResponseEntity<MessageResponse> wrongPassword = rest.postForEntity("/api/auth/login",
                new LoginRequest("carol", "Wr0ngPass1"), MessageResponse.class);
        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<MessageResponse> unknown = rest.postForEntity("/api/auth/login",
                new LoginRequest("nobody", "Wr0ngPass1"), MessageResponse.class);
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        List<AuditEvent> failures = auditEventRepository.findByType(AuditEventType.LOGIN_FAILURE);
        assertThat(failures).isNotEmpty();
    }

    private static HttpEntity<Void> bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        return new HttpEntity<>(headers);
    }
}
