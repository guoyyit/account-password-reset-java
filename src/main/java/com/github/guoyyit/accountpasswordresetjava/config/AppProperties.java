package com.github.guoyyit.accountpasswordresetjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app")
public class AppProperties {

    /** 会话有效期 */
    private Duration sessionTtl = Duration.ofHours(24);

    /** 重置凭据有效期 */
    private Duration resetTokenTtl = Duration.ofMinutes(10);

    /** 重置凭据允许的最大校验失败次数，超过后凭据作废 */
    private int resetMaxAttempts = 5;

    /** 同一账户申请重置凭据的限流窗口 */
    private Duration resetRequestWindow = Duration.ofMinutes(10);

    /** 限流窗口内允许的最大申请次数 */
    private int resetRequestMax = 3;

    /** 本地模拟投递的 outbox 目录 */
    private String outboxDir = "./data/outbox";

    public Duration getSessionTtl() {
        return sessionTtl;
    }

    public void setSessionTtl(Duration sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    public Duration getResetTokenTtl() {
        return resetTokenTtl;
    }

    public void setResetTokenTtl(Duration resetTokenTtl) {
        this.resetTokenTtl = resetTokenTtl;
    }

    public int getResetMaxAttempts() {
        return resetMaxAttempts;
    }

    public void setResetMaxAttempts(int resetMaxAttempts) {
        this.resetMaxAttempts = resetMaxAttempts;
    }

    public Duration getResetRequestWindow() {
        return resetRequestWindow;
    }

    public void setResetRequestWindow(Duration resetRequestWindow) {
        this.resetRequestWindow = resetRequestWindow;
    }

    public int getResetRequestMax() {
        return resetRequestMax;
    }

    public void setResetRequestMax(int resetRequestMax) {
        this.resetRequestMax = resetRequestMax;
    }

    public String getOutboxDir() {
        return outboxDir;
    }

    public void setOutboxDir(String outboxDir) {
        this.outboxDir = outboxDir;
    }
}
