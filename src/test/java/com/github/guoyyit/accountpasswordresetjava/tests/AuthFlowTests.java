package com.github.guoyyit.accountpasswordresetjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.accountpasswordresetjava.account.AccountRepository;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordAccount;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordHistoryRepository;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.reset.LocalResetDelivery;
import com.github.guoyyit.accountpasswordresetjava.reset.ResetCredentialRepository;
import com.github.guoyyit.accountpasswordresetjava.session.SessionRepository;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:authflow;DB_CLOSE_DELAY=-1",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class AuthFlowTests {

    private static final String PASSWORD = "Str0ng!Passw0rd";
    private static final ObjectMapper MAPPER = new ObjectMapper();

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
    void registerStoresPasswordInIrreversibleForm() {
        ResponseEntity<JsonNode> response = register("alice@example.com", PASSWORD);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        PasswordAccount account = accounts.findByUsername("alice@example.com").orElseThrow();
        assertThat(account.getPasswordHash()).startsWith("pbkdf2$");
        assertThat(account.getPasswordHash()).doesNotContain(PASSWORD);
        assertThat(history.findByAccountId(account.getId())).hasSize(1);
    }

    @Test
    void registerRejectsWeakPassword() {
        ResponseEntity<JsonNode> shortPassword = register("bob@example.com", "Ab1!");
        assertThat(shortPassword.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(shortPassword.getBody().get("error").asText()).isEqualTo("password_too_short");

        ResponseEntity<JsonNode> weakPassword = register("bob@example.com", "alllowercase1!");
        assertThat(weakPassword.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(weakPassword.getBody().get("error").asText()).isEqualTo("password_too_weak");

        assertThat(accounts.findByUsername("bob@example.com")).isEmpty();
    }

    @Test
    void registerRejectsDuplicateUsernameCaseInsensitively() {
        assertThat(register("carol@example.com", PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.CREATED);
        ResponseEntity<JsonNode> duplicate = register("Carol@Example.com", PASSWORD);
        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(duplicate.getBody().get("error").asText()).isEqualTo("username_unavailable");
    }

    @Test
    void loginIssuesSessionAndLogoutRevokesIt() throws Exception {
        register("dave@example.com", PASSWORD);
        ResponseEntity<JsonNode> login = login("dave@example.com", PASSWORD);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = login.getBody().get("sessionToken").asText();
        String sessionId = login.getBody().get("sessionId").asText();

        ResponseEntity<JsonNode> session = getSession(token);
        assertThat(session.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(session.getBody().get("username").asText()).isEqualTo("dave@example.com");
        assertThat(session.getBody().get("sessionId").asText()).isEqualTo(sessionId);

        assertThat(logout(token).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(getSession(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void loginFailureIsIndistinguishableForUnknownAccount() {
        register("erin@example.com", PASSWORD);
        ResponseEntity<JsonNode> wrongPassword = login("erin@example.com", "Wr0ng!Passw0rd");
        ResponseEntity<JsonNode> unknownAccount = login("nobody@example.com", "Wr0ng!Passw0rd");

        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownAccount.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownAccount.getBody()).isEqualTo(wrongPassword.getBody());
    }

    @Test
    void sessionTokenIsStoredIrreversibly() {
        register("frank@example.com", PASSWORD);
        String token = login("frank@example.com", PASSWORD).getBody()
                .get("sessionToken").asText();
        assertThat(sessions.findAll()).allSatisfy(session -> {
            assertThat(session.getTokenHash()).doesNotContain(token);
            assertThat(session.getTokenHash()).hasSize(64);
        });
    }

    @Test
    void revokeSessionByIdRequiresOwnership() throws Exception {
        register("grace@example.com", PASSWORD);
        register("heidi@example.com", PASSWORD);
        JsonNode graceLogin = login("grace@example.com", PASSWORD).getBody();
        JsonNode heidiLogin = login("heidi@example.com", PASSWORD).getBody();
        String graceToken = graceLogin.get("sessionToken").asText();
        String heidiToken = heidiLogin.get("sessionToken").asText();
        String heidiSessionId = heidiLogin.get("sessionId").asText();

        ResponseEntity<JsonNode> forbidden = deleteSession(graceToken, heidiSessionId);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(forbidden.getBody().get("error").asText()).isEqualTo("forbidden");
        assertThat(getSession(heidiToken).getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<JsonNode> own = deleteSession(heidiToken, heidiSessionId);
        assertThat(own.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(getSession(heidiToken).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void missingOrMalformedBearerTokenIsRejected() {
        ResponseEntity<JsonNode> noHeader = rest.getForEntity("/api/auth/session", JsonNode.class);
        assertThat(noHeader.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<JsonNode> garbage = getSession("not-a-real-token");
        assertThat(garbage.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(garbage.getBody().get("error").asText()).isEqualTo("invalid_session");
    }

    @Test
    void keyEventsAreAudited() {
        register("ivan@example.com", PASSWORD);
        String token = login("ivan@example.com", PASSWORD).getBody().get("sessionToken").asText();
        logout(token);

        List<String> eventTypes = audits.findAll().stream().map(AuditEvent::getEventType).toList();
        assertThat(eventTypes).contains("ACCOUNT_REGISTERED", "LOGIN_SUCCEEDED",
                "SESSION_ISSUED", "SESSION_REVOKED");
    }

    private ResponseEntity<JsonNode> register(String username, String password) {
        return post("/api/accounts/register",
                Map.of("username", username, "password", password), null);
    }

    private ResponseEntity<JsonNode> login(String username, String password) {
        return post("/api/auth/login",
                Map.of("username", username, "password", password), null);
    }

    private ResponseEntity<JsonNode> logout(String token) {
        return post("/api/auth/logout", null, token);
    }

    private ResponseEntity<JsonNode> getSession(String token) {
        return exchange("/api/auth/session", HttpMethod.GET, null, token);
    }

    private ResponseEntity<JsonNode> deleteSession(String token, String sessionId) {
        return exchange("/api/sessions/" + sessionId, HttpMethod.DELETE, null, token);
    }

    private ResponseEntity<JsonNode> post(String path, Object body, String token) {
        return exchange(path, HttpMethod.POST, body, token);
    }

    private ResponseEntity<JsonNode> exchange(String path, HttpMethod method, Object body,
                                              String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(path, method, new HttpEntity<>(body, headers), JsonNode.class);
    }
}
