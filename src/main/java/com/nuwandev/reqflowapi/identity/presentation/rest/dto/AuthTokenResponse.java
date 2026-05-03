package com.nuwandev.reqflowapi.identity.presentation.rest.dto;

import com.nuwandev.reqflowapi.identity.application.port.input.AuthTokens;

public record AuthTokenResponse(String accessToken) {
    public static AuthTokenResponse from(AuthTokens tokens) {
        return new AuthTokenResponse(tokens.accessToken());
    }
}
