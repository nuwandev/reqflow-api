package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.LogoutCommand;
import com.nuwandev.reqflowapi.identity.application.port.input.LogoutUseCase;
import com.nuwandev.reqflowapi.identity.application.port.output.AuthAuditLogger;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class LogoutService implements LogoutUseCase {

    private final AuthSessionRepository authSessionRepository;
    private final AuthAuditLogger authAuditLogger;
    private final Clock clock;

    public LogoutService(AuthSessionRepository authSessionRepository, AuthAuditLogger authAuditLogger, Clock clock) {
        this.authSessionRepository = authSessionRepository;
        this.authAuditLogger = authAuditLogger;
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
        authAuditLogger.logoutSucceeded(command.tenantId(), command.userId());
    }
}

