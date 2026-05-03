package com.nuwandev.reqflowapi.auth.application.port.input;

public interface RefreshTokenUseCase {

    AuthTokens execute(RefreshTokenCommand command);
}

