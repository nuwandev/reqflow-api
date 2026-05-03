package com.nuwandev.reqflowapi.identity.application.port.input;

public interface RefreshTokenUseCase {

    AuthTokens execute(RefreshTokenCommand command);
}

