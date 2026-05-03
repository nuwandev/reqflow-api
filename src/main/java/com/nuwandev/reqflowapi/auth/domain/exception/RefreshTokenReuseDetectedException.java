package com.nuwandev.reqflowapi.auth.domain.exception;

public class RefreshTokenReuseDetectedException extends RuntimeException {

    public RefreshTokenReuseDetectedException() {
        super("Refresh token reuse detected");
    }
}

