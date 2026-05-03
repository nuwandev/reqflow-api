package com.nuwandev.reqflowapi.identity.application.port.input;

public record AuthTokens(
        String accessToken,
        String refreshToken
) {
}

