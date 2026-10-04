package com.github.guoyyit.accountpasswordresetjava.web.dto;

import java.time.Instant;

public record LoginResponse(String sessionToken, Instant expiresAt) {
}
