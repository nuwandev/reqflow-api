package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.LogoutCommand;
import com.nuwandev.reqflowapi.identity.application.port.input.LogoutUseCase;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class LogoutService implements LogoutUseCase {

    private final AuthSessionRepository authSessionRepository;
    private final Clock clock;

    public LogoutService(AuthSessionRepository authSessionRepository, Clock clock) {
        this.authSessionRepository = authSessionRepository;
        this.clock = clock;
    }

    private static void validate(LogoutCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("Logout command cannot be null");
        }
        if (command.tenantId() == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (command.userId() == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }
    }

    @Override
    @Transactional
    public void execute(LogoutCommand command) {
        validate(command);
        authSessionRepository.revokeAllByUserId(
                command.tenantId(),
                command.userId(),
                Instant.now(clock)
        );
    }
}

