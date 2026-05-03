package com.nuwandev.reqflowapi.auth.presentation.rest.dto;

import com.nuwandev.reqflowapi.auth.application.port.input.AuthTokens;

public record AuthTokenResponse(String accessToken) {
    public static AuthTokenResponse from(AuthTokens tokens) {
        return new AuthTokenResponse(tokens.accessToken());
    }
}
