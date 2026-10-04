package com.github.guoyyit.accountpasswordresetjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.guoyyit.accountpasswordresetjava.account.AccountRepository;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordAccount;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordHistoryRepository;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.reset.LocalResetDelivery;
import com.github.guoyyit.accountpasswordresetjava.reset.ResetCredential;
import com.github.guoyyit.accountpasswordresetjava.reset.ResetCredentialRepository;
import com.github.guoyyit.accountpasswordresetjava.session.SessionRepository;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:resetflow;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class PasswordResetTests {

    private static final String PASSWORD = "Str0ng!Passw0rd";
    private static final String NEW_PASSWORD = "N3w!Passw0rdXy";
    private static final String THIRD_PASSWORD = "Th1rd!Passw0rd";

    @Autowired
    private TestRestTemplate rest;
    @Autowired
    private AccountRepository accounts;
    @Autowired
    private PasswordHistoryRepository history;
    @Autowired
    private SessionRepository sessions;
    @Autowired
    private ResetCredentialRepository credentials;
    @Autowired
    private AuditEventRepository audits;
    @Autowired
    private LocalResetDelivery delivery;

    @BeforeEach
    void clean() {
        credentials.deleteAll();
        sessions.deleteAll();
        history.deleteAll();
        accounts.deleteAll();
        audits.deleteAll();
        delivery.clear();
    }

    @Test
    void resetRequestIsIndistinguishableForUnknownAccount() {
        register("known@example.com", PASSWORD);

        ResponseEntity<JsonNode> known = requestReset("known@example.com");
        ResponseEntity<JsonNode> unknown = requestReset("ghost@example.com");

        assertThat(known.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(unknown.getBody()).isEqualTo(known.getBody());
        assertThat(delivery.deliveriesFor("ghost@example.com")).isEmpty();
        assertThat(delivery.deliveriesFor("known@example.com")).hasSize(1);
    }

    @Test
    void fullResetFlowSucceedsAndRevokesOldCredentials() {
        register("flow@example.com", PASSWORD);
        String oldSession = login("flow@example.com", PASSWORD).getBody()
                .get("sessionToken").asText();

        requestReset("flow@example.com");
        String token = latestToken("flow@example.com");

        assertThat(verify(token).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(confirm(token, NEW_PASSWORD).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        assertThat(getSession(oldSession).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(login("flow@example.com", PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(login("flow@example.com", NEW_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.OK);

        List<String> eventTypes = audits.findAll().stream().map(AuditEvent::getEventType).toList();
        assertThat(eventTypes).contains("RESET_CREDENTIAL_ISSUED", "RESET_VERIFY_SUCCEEDED",
                "RESET_CONFIRM_SUCCEEDED", "PASSWORD_RESET_SUCCEEDED", "SESSIONS_REVOKED_ALL");
    }

    @Test
    void credentialCannotBeReplayedOnceUsed() {
        register("replay@example.com", PASSWORD);
        requestReset("replay@example.com");
        String token = latestToken("replay@example.com");

        assertThat(confirm(token, NEW_PASSWORD).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<JsonNode> replayed = confirm(token, THIRD_PASSWORD);
        assertThat(replayed.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(replayed.getBody().get("error").asText()).isEqualTo("invalid_credential");
        assertThat(verify(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(login("replay@example.com", NEW_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void expiredCredentialIsRejectedWithUniformError() {
        register("expiry@example.com", PASSWORD);
        requestReset("expiry@example.com");
        String token = latestToken("expiry@example.com");

        PasswordAccount account = accounts.findByUsername("expiry@example.com").orElseThrow();
        ResetCredential credential = credentials
                .findByAccountIdAndUsedAtIsNullAndSupersededAtIsNull(account.getId())
                .get(0);
        credential.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));
        credentials.save(credential);

        ResponseEntity<JsonNode> verifyResponse = verify(token);
        ResponseEntity<JsonNode> confirmResponse = confirm(token, NEW_PASSWORD);
        assertThat(verifyResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(confirmResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(confirmResponse.getBody()).isEqualTo(verifyResponse.getBody());
    }

    @Test
    void malformedAndUnknownCredentialsGetSameErrorAsExpired() {
        register("uniform@example.com", PASSWORD);
        requestReset("uniform@example.com");
        String token = latestToken("uniform@example.com");
        PasswordAccount account = accounts.findByUsername("uniform@example.com").orElseThrow();
        ResetCredential credential = credentials
                .findByAccountIdAndUsedAtIsNullAndSupersededAtIsNull(account.getId())
                .get(0);
        credential.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));
        credentials.save(credential);

        ResponseEntity<JsonNode> expired = confirm(token, NEW_PASSWORD);
        ResponseEntity<JsonNode> malformed = confirm("not-a-token", NEW_PASSWORD);
        ResponseEntity<JsonNode> unknown = confirm(
                "rst_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", NEW_PASSWORD);

        for (ResponseEntity<JsonNode> response : List.of(expired, malformed, unknown)) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
        assertThat(malformed.getBody()).isEqualTo(expired.getBody());
        assertThat(unknown.getBody()).isEqualTo(expired.getBody());
    }

    @Test
    void newRequestSupersedesPreviousCredential() {
        register("supersede@example.com", PASSWORD);
        requestReset("supersede@example.com");
        String first = latestToken("supersede@example.com");
        requestReset("supersede@example.com");
        String second = latestToken("supersede@example.com");
        assertThat(second).isNotEqualTo(first);

        assertThat(verify(first).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(verify(second).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(confirm(first, NEW_PASSWORD).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(confirm(second, NEW_PASSWORD).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void passwordHistoryIsEnforcedAcrossResets() {
        register("history@example.com", PASSWORD);

        requestReset("history@example.com");
        assertThat(confirm(latestToken("history@example.com"), NEW_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);

        requestReset("history@example.com");
        String token = latestToken("history@example.com");
        ResponseEntity<JsonNode> reuseInitial = confirm(token, PASSWORD);
        assertThat(reuseInitial.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(reuseInitial.getBody().get("error").asText()).isEqualTo("password_reused");

        ResponseEntity<JsonNode> reuseCurrent = confirm(token, NEW_PASSWORD);
        assertThat(reuseCurrent.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(reuseCurrent.getBody().get("error").asText()).isEqualTo("password_reused");

        assertThat(verify(token).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(confirm(token, THIRD_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(login("history@example.com", THIRD_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void weakPasswordRejectedAndCredentialRemainsUsable() {
        register("weak@example.com", PASSWORD);
        requestReset("weak@example.com");
        String token = latestToken("weak@example.com");

        ResponseEntity<JsonNode> weak = confirm(token, "alllowercase1!");
        assertThat(weak.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(weak.getBody().get("error").asText()).isEqualTo("password_too_weak");

        assertThat(verify(token).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(confirm(token, NEW_PASSWORD).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void rateLimitStopsIssuingWhileResponseStaysUniform() {
        register("limited@example.com", PASSWORD);

        for (int i = 0; i < 5; i++) {
            ResponseEntity<JsonNode> response = requestReset("limited@example.com");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        }
        assertThat(delivery.deliveriesFor("limited@example.com")).hasSize(3);

        List<String> eventTypes = audits.findAll().stream().map(AuditEvent::getEventType).toList();
        assertThat(eventTypes).contains("RESET_REQUEST_RATE_LIMITED");
    }

    @Test
    void resetRevokesAllExistingSessions() {
        register("sessions@example.com", PASSWORD);
        String sessionA = login("sessions@example.com", PASSWORD).getBody()
                .get("sessionToken").asText();
        String sessionB = login("sessions@example.com", PASSWORD).getBody()
                .get("sessionToken").asText();

        requestReset("sessions@example.com");
        assertThat(confirm(latestToken("sessions@example.com"), NEW_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);

        assertThat(getSession(sessionA).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(getSession(sessionB).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private String latestToken(String username) {
        List<LocalResetDelivery.Delivery> deliveries = delivery.deliveriesFor(username);
        assertThat(deliveries).isNotEmpty();
        return deliveries.get(deliveries.size() - 1).rawToken();
    }

    private ResponseEntity<JsonNode> register(String username, String password) {
        return exchange("/api/accounts/register", Map.of("username", username,
                "password", password), null);
    }

    private ResponseEntity<JsonNode> login(String username, String password) {
        return exchange("/api/auth/login", Map.of("username", username,
                "password", password), null);
    }

    private ResponseEntity<JsonNode> requestReset(String username) {
        return exchange("/api/password-reset/request", Map.of("username", username), null);
    }

    private ResponseEntity<JsonNode> verify(String token) {
        return exchange("/api/password-reset/verify", Map.of("token", token), null);
    }

    private ResponseEntity<JsonNode> confirm(String token, String newPassword) {
        return exchange("/api/password-reset/confirm",
                Map.of("token", token, "newPassword", newPassword), null);
    }

    private ResponseEntity<JsonNode> getSession(String token) {
        return exchange("/api/auth/session", null, token);
    }

    private ResponseEntity<JsonNode> exchange(String path, Object body, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        HttpMethod method = body == null ? HttpMethod.GET : HttpMethod.POST;
        return rest.exchange(path, method, new HttpEntity<>(body, headers), JsonNode.class);
    }
}
