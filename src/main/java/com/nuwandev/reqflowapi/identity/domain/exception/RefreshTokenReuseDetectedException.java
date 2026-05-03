package com.nuwandev.reqflowapi.identity.domain.exception;

public class RefreshTokenReuseDetectedException extends RuntimeException {

    public RefreshTokenReuseDetectedException() {
        super("Refresh token reuse detected");
    }
}

