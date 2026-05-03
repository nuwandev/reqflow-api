package com.nuwandev.reqflowapi.identity.infrastructure.security;

public class InvalidAccessTokenException extends RuntimeException {

    public InvalidAccessTokenException(String message) {
        super(message);
    }
}

