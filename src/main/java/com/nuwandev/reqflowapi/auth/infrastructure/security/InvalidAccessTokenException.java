package com.nuwandev.reqflowapi.auth.infrastructure.security;

public class InvalidAccessTokenException extends RuntimeException {

    public InvalidAccessTokenException(String message) {
        super(message);
    }
}

