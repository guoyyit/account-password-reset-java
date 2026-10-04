package com.github.guoyyit.accountpasswordresetjava.web;

public class AccessDeniedException extends RuntimeException {

    public AccessDeniedException(String message) {
        super(message);
    }
}
