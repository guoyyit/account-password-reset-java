package com.github.guoyyit.accountpasswordresetjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.reset.LocalResetDelivery;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:file:./target/test-data/restartdb;DB_CLOSE_ON_EXIT=FALSE",
        "spring.jpa.hibernate.ddl-auto=update"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RestartRecoveryTests {

    private static final String PASSWORD = "Str0ng!Passw0rd";
    private static final String NEW_PASSWORD = "N3w!Passw0rdXy";

    private static String pendingToken;
    private static String sessionToken;
    private static long auditCountBeforeRestart;

    @Autowired
    private TestRestTemplate rest;
    @Autowired
    private LocalResetDelivery delivery;
    @Autowired
    private AuditEventRepository audits;

    @BeforeAll
    static void wipeDatabaseFiles() throws IOException {
        Path dir = Path.of("./target/test-data");
        if (Files.exists(dir)) {
            try (var stream = Files.walk(dir)) {
                stream.sorted(Comparator.reverseOrder())
                        .forEach(path -> path.toFile().delete());
            }
        }
    }

    @Test
    @Order(1)
    @DirtiesContext
    void step1_registerLoginAndRequestReset() {
        ResponseEntity<JsonNode> register = post("/api/accounts/register",
                Map.of("username", "restart@example.com", "password", PASSWORD));
        assertThat(register.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<JsonNode> login = post("/api/auth/login",
                Map.of("username", "restart@example.com", "password", PASSWORD));
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        sessionToken = login.getBody().get("sessionToken").asText();

        ResponseEntity<JsonNode> request = post("/api/password-reset/request",
                Map.of("username", "restart@example.com"));
        assertThat(request.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

        List<LocalResetDelivery.Delivery> deliveries = delivery.deliveriesFor("restart@example.com");
        assertThat(deliveries).hasSize(1);
        pendingToken = deliveries.get(0).rawToken();
        auditCountBeforeRestart = audits.count();
        assertThat(auditCountBeforeRestart).isGreaterThan(0);
    }

    @Test
    @Order(2)
    @DirtiesContext
    void step2_afterRestartUnusedCredentialStillWorks() {
        assertThat(audits.count()).as("audit log survives restart")
                .isGreaterThanOrEqualTo(auditCountBeforeRestart);

        ResponseEntity<JsonNode> session = getSession(sessionToken);
        assertThat(session.getStatusCode()).as("active session survives restart")
                .isEqualTo(HttpStatus.OK);

        ResponseEntity<JsonNode> verify = post("/api/password-reset/verify",
                Map.of("token", pendingToken));
        assertThat(verify.getStatusCode()).as("unused credential survives restart")
                .isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<JsonNode> confirm = post("/api/password-reset/confirm",
                Map.of("token", pendingToken, "newPassword", NEW_PASSWORD));
        assertThat(confirm.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<JsonNode> oldLogin = post("/api/auth/login",
                Map.of("username", "restart@example.com", "password", PASSWORD));
        assertThat(oldLogin.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        ResponseEntity<JsonNode> newLogin = post("/api/auth/login",
                Map.of("username", "restart@example.com", "password", NEW_PASSWORD));
        assertThat(newLogin.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @Order(3)
    void step3_afterSecondRestartUsedCredentialStaysUsed() {
        ResponseEntity<JsonNode> verify = post("/api/password-reset/verify",
                Map.of("token", pendingToken));
        assertThat(verify.getStatusCode()).as("used credential must not revive after restart")
                .isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<JsonNode> confirm = post("/api/password-reset/confirm",
                Map.of("token", pendingToken, "newPassword", "An0ther!Passw0rd"));
        assertThat(confirm.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(confirm.getBody().get("error").asText()).isEqualTo("invalid_credential");

        ResponseEntity<JsonNode> session = getSession(sessionToken);
        assertThat(session.getStatusCode()).as("revoked session stays revoked after restart")
                .isEqualTo(HttpStatus.UNAUTHORIZED);

        List<String> eventTypes = audits.findAll().stream().map(AuditEvent::getEventType).toList();
        assertThat(eventTypes).contains("ACCOUNT_REGISTERED", "RESET_CREDENTIAL_ISSUED",
                "RESET_CONFIRM_SUCCEEDED", "SESSIONS_REVOKED_ALL");
    }

    private ResponseEntity<JsonNode> post(String path, Object body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.postForEntity(path, new HttpEntity<>(body, headers), JsonNode.class);
    }

    private ResponseEntity<JsonNode> getSession(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return rest.exchange("/api/auth/session", org.springframework.http.HttpMethod.GET,
                new HttpEntity<>(headers), JsonNode.class);
    }
}
