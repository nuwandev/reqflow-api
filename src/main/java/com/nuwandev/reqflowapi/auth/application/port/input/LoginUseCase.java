package com.nuwandev.reqflowapi.auth.application.port.input;

public interface LoginUseCase {

    AuthTokens execute(LoginCommand command);
}

