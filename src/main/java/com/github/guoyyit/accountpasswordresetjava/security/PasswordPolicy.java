package com.github.guoyyit.accountpasswordresetjava.security;

import org.springframework.stereotype.Component;

@Component
public class PasswordPolicy {

    private static final int MIN_LENGTH = 10;
    private static final int MAX_LENGTH = 128;

    public String checkViolation(String username, String rawPassword) {
        if (rawPassword == null || rawPassword.length() < MIN_LENGTH) {
            return "password_too_short";
        }
        if (rawPassword.length() > MAX_LENGTH) {
            return "password_too_long";
        }
        boolean hasLower = false;
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        for (int i = 0; i < rawPassword.length(); i++) {
            char c = rawPassword.charAt(i);
            if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }
        if (!hasLower || !hasUpper || !hasDigit || !hasSpecial) {
            return "password_too_weak";
        }
        if (username != null && !username.isBlank()
                && rawPassword.toLowerCase().contains(username.toLowerCase())) {
            return "password_contains_username";
        }
        return null;
    }

    public String describe() {
        return "length " + MIN_LENGTH + "-" + MAX_LENGTH
                + ", must contain lowercase, uppercase, digit and special character"
                + ", must not contain the username";
    }
}
