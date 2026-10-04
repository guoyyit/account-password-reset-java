package com.github.guoyyit.accountpasswordresetjava.service;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimiter {

    private final Map<String, Deque<Instant>> hits = new ConcurrentHashMap<>();

    public boolean tryAcquire(String key, int maxPermits, Duration window) {
        Instant now = Instant.now();
        Deque<Instant> deque = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (deque) {
            Instant cutoff = now.minus(window);
            while (!deque.isEmpty() && deque.peekFirst().isBefore(cutoff)) {
                deque.pollFirst();
            }
            if (deque.size() >= maxPermits) {
                return false;
            }
            deque.addLast(now);
            return true;
        }
    }

    public void clear() {
        hits.clear();
    }
}
