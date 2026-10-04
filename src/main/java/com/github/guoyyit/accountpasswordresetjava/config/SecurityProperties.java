package com.github.guoyyit.accountpasswordresetjava.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private Duration sessionTtl = Duration.ofHours(12);
    private Duration resetTokenTtl = Duration.ofMinutes(15);
    private int resetRateLimitMax = 3;
    private Duration resetRateLimitWindow = Duration.ofMinutes(10);

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

    public int getResetRateLimitMax() {
        return resetRateLimitMax;
    }

    public void setResetRateLimitMax(int resetRateLimitMax) {
        this.resetRateLimitMax = resetRateLimitMax;
    }

    public Duration getResetRateLimitWindow() {
        return resetRateLimitWindow;
    }

    public void setResetRateLimitWindow(Duration resetRateLimitWindow) {
        this.resetRateLimitWindow = resetRateLimitWindow;
    }
}
