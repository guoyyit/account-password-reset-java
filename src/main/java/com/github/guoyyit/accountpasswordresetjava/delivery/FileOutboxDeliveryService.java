package com.github.guoyyit.accountpasswordresetjava.delivery;

import com.github.guoyyit.accountpasswordresetjava.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 本地模拟的投递渠道：消息写入本地 outbox 目录并保留内存副本，便于本地端到端验证。
 */
@Service
public class FileOutboxDeliveryService implements LocalDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(FileOutboxDeliveryService.class);

    private final Path outboxDir;
    private final ConcurrentHashMap<String, CopyOnWriteArrayList<String>> inMemoryOutbox = new ConcurrentHashMap<>();

    public FileOutboxDeliveryService(AppProperties properties) {
        this.outboxDir = Path.of(properties.getOutboxDir());
    }

    @Override
    public void deliver(String recipient, String message) {
        String line = "[" + Instant.now() + "] " + message;
        inMemoryOutbox.computeIfAbsent(recipient, k -> new CopyOnWriteArrayList<>()).add(line);
        try {
            Files.createDirectories(outboxDir);
            Path file = outboxDir.resolve(sanitize(recipient) + ".txt");
            Files.writeString(file, line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to write local outbox", e);
        }
        log.info("local delivery to {}: {}", recipient, message);
    }

    @Override
    public List<String> outboxFor(String recipient) {
        return List.copyOf(inMemoryOutbox.getOrDefault(recipient, new CopyOnWriteArrayList<>()));
    }

    private static String sanitize(String recipient) {
        return recipient.replaceAll("[^a-zA-Z0-9_.-]", "_");
    }
}
