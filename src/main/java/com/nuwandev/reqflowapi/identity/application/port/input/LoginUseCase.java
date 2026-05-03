package com.nuwandev.reqflowapi.identity.application.port.input;

public interface LoginUseCase {

    AuthTokens execute(LoginCommand command);
}

