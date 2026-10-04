package com.github.guoyyit.accountpasswordresetjava.tests;

import com.github.guoyyit.accountpasswordresetjava.delivery.LocalDeliveryService;
import com.github.guoyyit.accountpasswordresetjava.model.Account;
import com.github.guoyyit.accountpasswordresetjava.model.ResetToken;
import com.github.guoyyit.accountpasswordresetjava.repository.ResetTokenRepository;
import com.github.guoyyit.accountpasswordresetjava.service.AccountService;
import com.github.guoyyit.accountpasswordresetjava.service.ResetService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 并发申请：同一账户同时发起多次申请，行为确定——最终恰好一个凭据可用。
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:concurrentreset;DB_CLOSE_DELAY=-1",
        "app.outbox-dir=target/test-outbox/concurrentreset",
        "app.reset-request-max=100",
        "app.reset-request-window=PT1M"
})
class ConcurrentResetRequestTest {

    private static final Pattern CODE_PATTERN = Pattern.compile("code: (\\d{6})");
    private static final int THREADS = 8;

    @Autowired
    private AccountService accountService;

    @Autowired
    private ResetService resetService;

    @Autowired
    private ResetTokenRepository resetTokenRepository;

    @Autowired
    private LocalDeliveryService deliveryService;

    @Test
    void concurrentRequestsLeaveExactlyOneUsableCredential() throws Exception {
        Account account = accountService.register("trent", "Str0ngPass");

        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch ready = new CountDownLatch(THREADS);
        CountDownLatch go = new CountDownLatch(1);
        List<Callable<String>> tasks = new ArrayList<>();
        for (int i = 0; i < THREADS; i++) {
            tasks.add(() -> {
                ready.countDown();
                go.await();
                resetService.requestReset("trent");
                return "ok";
            });
        }
        List<Future<String>> futures = tasks.stream().map(pool::submit).toList();
        ready.await(10, TimeUnit.SECONDS);
        go.countDown();
        for (Future<String> future : futures) {
            future.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        List<ResetToken> tokens = resetTokenRepository.findByAccountId(account.getId());
        assertThat(tokens).hasSize(THREADS);
        List<ResetToken> usable = tokens.stream().filter(t -> t.isUsable(Instant.now())).toList();
        assertThat(usable).as("exactly one credential usable after concurrent requests").hasSize(1);

        List<String> delivered = deliveryService.outboxFor("trent");
        assertThat(delivered).hasSize(THREADS);
        int verifyOk = 0;
        for (String message : delivered) {
            Matcher matcher = CODE_PATTERN.matcher(message);
            assertThat(matcher.find()).isTrue();
            try {
                resetService.verify("trent", matcher.group(1));
                verifyOk++;
            } catch (Exception rejected) {
                // 其余凭据必须被统一拒绝
            }
        }
        assertThat(verifyOk).as("exactly one delivered code verifies").isEqualTo(1);
    }
}
