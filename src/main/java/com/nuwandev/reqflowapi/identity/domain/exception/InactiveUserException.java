package com.nuwandev.reqflowapi.identity.domain.exception;

public class InactiveUserException extends RuntimeException {

    public InactiveUserException() {
        super("User is inactive");
    }
}

