package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.Application;
import com.github.guoyyit.accountpasswordresetjava.delivery.LocalDeliveryService;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEvent;
import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.repository.AuditEventRepository;
import com.github.guoyyit.accountpasswordresetjava.service.AccountService;
import com.github.guoyyit.accountpasswordresetjava.service.ResetService;
import com.github.guoyyit.accountpasswordresetjava.web.ApiException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 重启恢复：未使用且未过期的凭据重启后仍可用；已使用的凭据不得恢复；审计记录不丢失。
 */
class RestartRecoveryTest {

    private static final Pattern CODE_PATTERN = Pattern.compile("code: (\\d{6})");

    @TempDir
    static Path tempDir;

    @Test
    void credentialsAndAuditSurviveRestart() {
        String aliceCode;
        String bobCode;

        try (ConfigurableApplicationContext ctx = startContext()) {
            AccountService accounts = ctx.getBean(AccountService.class);
            ResetService resets = ctx.getBean(ResetService.class);
            LocalDeliveryService delivery = ctx.getBean(LocalDeliveryService.class);

            accounts.register("alice", "OldPassw0rd");
            accounts.register("bob", "OldPassw0rd");

            resets.requestReset("alice");
            aliceCode = latestCode(delivery, "alice");

            resets.requestReset("bob");
            bobCode = latestCode(delivery, "bob");
            resets.confirm("bob", bobCode, "N3wPassw0rd");
        }

        try (ConfigurableApplicationContext ctx = startContext()) {
            ResetService resets = ctx.getBean(ResetService.class);
            AccountService accounts = ctx.getBean(AccountService.class);
            AuditEventRepository audits = ctx.getBean(AuditEventRepository.class);

            resets.verify("alice", aliceCode);
            resets.confirm("alice", aliceCode, "AliceNew1pass");
            assertThat(accounts.login("alice", "AliceNew1pass").token()).isNotBlank();

            assertThatThrownBy(() -> resets.verify("bob", bobCode))
                    .isInstanceOf(ApiException.class)
                    .hasMessage("invalid or expired reset credential");
            assertThatThrownBy(() -> resets.confirm("bob", bobCode, "An0therPass1"))
                    .isInstanceOf(ApiException.class)
                    .hasMessage("invalid or expired reset credential");

            List<AuditEventType> aliceEvents = audits.findByUsernameOrderByCreatedAtAsc("alice")
                    .stream().map(AuditEvent::getType).toList();
            assertThat(aliceEvents).contains(AuditEventType.ACCOUNT_REGISTERED,
                    AuditEventType.RESET_REQUESTED,
                    AuditEventType.RESET_VERIFY_SUCCESS,
                    AuditEventType.RESET_CONFIRM_SUCCESS);

            List<AuditEventType> bobEvents = audits.findByUsernameOrderByCreatedAtAsc("bob")
                    .stream().map(AuditEvent::getType).toList();
            assertThat(bobEvents).contains(AuditEventType.RESET_CONFIRM_SUCCESS,
                    AuditEventType.SESSIONS_REVOKED_ALL);
        }
    }

    private static ConfigurableApplicationContext startContext() {
        return new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=jdbc:h2:file:" + tempDir.resolve("appdb"),
                        "--spring.datasource.username=sa",
                        "--spring.datasource.password=",
                        "--spring.jpa.hibernate.ddl-auto=update",
                        "--app.outbox-dir=" + tempDir.resolve("outbox"));
    }

    private static String latestCode(LocalDeliveryService delivery, String username) {
        List<String> outbox = delivery.outboxFor(username);
        assertThat(outbox).isNotEmpty();
        Matcher matcher = CODE_PATTERN.matcher(outbox.get(outbox.size() - 1));
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
