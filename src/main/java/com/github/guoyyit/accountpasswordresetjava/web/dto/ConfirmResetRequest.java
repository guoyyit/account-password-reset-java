package com.github.guoyyit.accountpasswordresetjava.web.dto;

public record ConfirmResetRequest(String username, String code, String newPassword) {
}
