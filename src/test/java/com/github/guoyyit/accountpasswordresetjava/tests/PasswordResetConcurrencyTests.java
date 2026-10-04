package com.github.guoyyit.accountpasswordresetjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.guoyyit.accountpasswordresetjava.account.AccountRepository;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordAccount;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordHistoryRepository;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.reset.LocalResetDelivery;
import com.github.guoyyit.accountpasswordresetjava.reset.ResetCredential;
import com.github.guoyyit.accountpasswordresetjava.reset.ResetCredentialRepository;
import com.github.guoyyit.accountpasswordresetjava.session.SessionRepository;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:resetconcurrency;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
        "spring.datasource.hikari.maximum-pool-size=20",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.security.reset-rate-limit-max=100"
})
class PasswordResetConcurrencyTests {

    private static final String PASSWORD = "Str0ng!Passw0rd";
    private static final String NEW_PASSWORD = "N3w!Passw0rdXy";
    private static final int THREADS = 6;

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
    void concurrentRequestsLeaveExactlyOneUsableCredential() throws Exception {
        register("race@example.com", PASSWORD);

        fireConcurrentRequests("race@example.com");

        PasswordAccount account = accounts.findByUsername("race@example.com").orElseThrow();
        List<ResetCredential> active = credentials
                .findByAccountIdAndUsedAtIsNullAndSupersededAtIsNull(account.getId());
        assertThat(active).as("exactly one active credential after concurrent requests").hasSize(1);

        List<LocalResetDelivery.Delivery> deliveries = delivery.deliveriesFor("race@example.com");
        assertThat(deliveries).hasSize(THREADS);

        List<String> usableTokens = new ArrayList<>();
        for (LocalResetDelivery.Delivery d : deliveries) {
            ResponseEntity<JsonNode> response = verify(d.rawToken());
            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                usableTokens.add(d.rawToken());
            } else {
                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                assertThat(response.getBody().get("error").asText())
                        .isEqualTo("invalid_credential");
            }
        }
        assertThat(usableTokens).as("exactly one delivered token remains usable").hasSize(1);

        assertThat(confirm(usableTokens.get(0), NEW_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(login("race@example.com", NEW_PASSWORD).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void concurrentRequestsAreDeterministicAcrossRepeatedBursts() throws Exception {
        register("repeat@example.com", PASSWORD);

        for (int burst = 0; burst < 2; burst++) {
            fireConcurrentRequests("repeat@example.com");
            PasswordAccount account = accounts.findByUsername("repeat@example.com").orElseThrow();
            List<ResetCredential> active = credentials
                    .findByAccountIdAndUsedAtIsNullAndSupersededAtIsNull(account.getId());
            assertThat(active).as("burst %d leaves exactly one active credential", burst)
                    .hasSize(1);
        }
    }

    private void fireConcurrentRequests(String username) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch ready = new CountDownLatch(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<ResponseEntity<JsonNode>>> futures = new ArrayList<>();
            for (int i = 0; i < THREADS; i++) {
                futures.add(pool.submit(requestTask(username, ready, start)));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            for (Future<ResponseEntity<JsonNode>> future : futures) {
                ResponseEntity<JsonNode> response = future.get(30, TimeUnit.SECONDS);
                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private Callable<ResponseEntity<JsonNode>> requestTask(String username,
                                                           CountDownLatch ready,
                                                           CountDownLatch start) {
        return () -> {
            ready.countDown();
            start.await();
            return requestReset(username);
        };
    }

    private void register(String username, String password) {
        ResponseEntity<JsonNode> response = post("/api/accounts/register",
                Map.of("username", username, "password", password));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    private ResponseEntity<JsonNode> requestReset(String username) {
        return post("/api/password-reset/request", Map.of("username", username));
    }

    private ResponseEntity<JsonNode> verify(String token) {
        return post("/api/password-reset/verify", Map.of("token", token));
    }

    private ResponseEntity<JsonNode> confirm(String token, String newPassword) {
        return post("/api/password-reset/confirm",
                Map.of("token", token, "newPassword", newPassword));
    }

    private ResponseEntity<JsonNode> login(String username, String password) {
        return post("/api/auth/login", Map.of("username", username, "password", password));
    }

    private ResponseEntity<JsonNode> post(String path, Object body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.postForEntity(path, new HttpEntity<>(body, headers), JsonNode.class);
    }
}
