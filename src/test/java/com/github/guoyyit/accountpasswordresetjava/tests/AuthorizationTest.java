package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.delivery.LocalDeliveryService;
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

/**
 * 越权防护：会话令牌与重置凭据均绑定其属主，跨账户使用一律拒绝。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:authorization;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/authorization"
})
class AuthorizationTest {

    private static final Pattern CODE_PATTERN = Pattern.compile("code: (\\d{6})");

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private LocalDeliveryService deliveryService;

    @Test
    void missingOrGarbageSessionTokenIsRejected() {
        ResponseEntity<MeResponse> noHeader = rest.getForEntity("/api/auth/me", MeResponse.class);
        assertThat(noHeader.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<MeResponse> garbage = rest.exchange("/api/auth/me", HttpMethod.GET,
                bearer("not-a-real-token"), MeResponse.class);
        assertThat(garbage.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<MessageResponse> logoutGarbage = rest.exchange("/api/auth/logout",
                HttpMethod.POST, bearer("not-a-real-token"), MessageResponse.class);
        assertThat(logoutGarbage.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void sessionTokenIsBoundToItsOwner() {
        register("usera", "Passw0rd!a");
        register("userb", "Passw0rd!b");
        String tokenA = login("usera", "Passw0rd!a");

        ResponseEntity<MeResponse> me = rest.exchange("/api/auth/me", HttpMethod.GET,
                bearer(tokenA), MeResponse.class);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody().username()).isEqualTo("usera");

        ResponseEntity<MessageResponse> logout = rest.exchange("/api/auth/logout", HttpMethod.POST,
                bearer(tokenA), MessageResponse.class);
        assertThat(logout.getStatusCode()).isEqualTo(HttpStatus.OK);

        String tokenB = login("userb", "Passw0rd!b");
        ResponseEntity<MeResponse> meB = rest.exchange("/api/auth/me", HttpMethod.GET,
                bearer(tokenB), MeResponse.class);
        assertThat(meB.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(meB.getBody().username()).isEqualTo("userb");
    }

    @Test
    void resetCredentialCannotBeUsedForAnotherAccount() {
        register("victim", "Passw0rd!v");
        register("attacker", "Passw0rd!a");

        rest.postForEntity("/api/reset/request", new RequestResetRequest("victim"), MessageResponse.class);
        String victimCode = latestCode("victim");

        ResponseEntity<MessageResponse> verifyOther = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("attacker", victimCode), MessageResponse.class);
        assertThat(verifyOther.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(verifyOther.getBody().message()).isEqualTo("invalid or expired reset credential");

        ResponseEntity<MessageResponse> confirmOther = rest.postForEntity("/api/reset/confirm",
                new ConfirmResetRequest("attacker", victimCode, "Hijacked1"), MessageResponse.class);
        assertThat(confirmOther.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(confirmOther.getBody().message()).isEqualTo("invalid or expired reset credential");

        ResponseEntity<LoginResponse> attackerLogin = rest.postForEntity("/api/auth/login",
                new LoginRequest("attacker", "Hijacked1"), LoginResponse.class);
        assertThat(attackerLogin.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<MessageResponse> verifyVictim = rest.postForEntity("/api/reset/verify",
                new VerifyResetRequest("victim", victimCode), MessageResponse.class);
        assertThat(verifyVictim.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private void register(String username, String password) {
        rest.postForEntity("/api/auth/register", new RegisterRequest(username, password),
                MessageResponse.class);
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
