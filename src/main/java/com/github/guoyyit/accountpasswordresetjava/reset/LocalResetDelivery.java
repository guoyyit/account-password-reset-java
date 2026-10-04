package com.github.guoyyit.accountpasswordresetjava.reset;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LocalResetDelivery implements ResetDelivery {

    public record Delivery(String username, String rawToken, Instant deliveredAt) {
    }

    private static final Logger log = LoggerFactory.getLogger(LocalResetDelivery.class);

    private final List<Delivery> outbox = new CopyOnWriteArrayList<>();

    @Override
    public void deliver(String username, String rawToken) {
        Delivery delivery = new Delivery(username, rawToken, Instant.now());
        outbox.add(delivery);
        log.info("local reset delivery: username={} token={}", username, rawToken);
    }

    public List<Delivery> deliveries() {
        return List.copyOf(outbox);
    }

    public List<Delivery> deliveriesFor(String username) {
        return outbox.stream().filter(d -> d.username().equals(username)).toList();
    }

    public void clear() {
        outbox.clear();
    }
}
