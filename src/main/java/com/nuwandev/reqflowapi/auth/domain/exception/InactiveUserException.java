package com.nuwandev.reqflowapi.auth.domain.exception;

public class InactiveUserException extends RuntimeException {

    public InactiveUserException() {
        super("User is inactive");
    }
}

