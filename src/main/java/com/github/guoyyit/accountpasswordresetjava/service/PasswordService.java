package com.github.guoyyit.accountpasswordresetjava.service;

import com.github.guoyyit.accountpasswordresetjava.web.ApiException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String passwordHash) {
        if (rawPassword == null || passwordHash == null) {
            return false;
        }
        return encoder.matches(rawPassword, passwordHash);
    }

    public void assertStrength(String rawPassword) {
        if (rawPassword == null
                || rawPassword.length() < MIN_LENGTH
                || rawPassword.length() > MAX_LENGTH
                || !rawPassword.chars().anyMatch(Character::isLetter)
                || !rawPassword.chars().anyMatch(Character::isDigit)) {
            throw ApiException.badRequest(
                    "password must be 8-128 characters and contain at least one letter and one digit");
        }
    }
}
