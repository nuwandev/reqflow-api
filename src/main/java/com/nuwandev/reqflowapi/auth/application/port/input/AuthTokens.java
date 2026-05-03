package com.nuwandev.reqflowapi.auth.application.port.input;

public record AuthTokens(
        String accessToken,
        String refreshToken
) {
}

