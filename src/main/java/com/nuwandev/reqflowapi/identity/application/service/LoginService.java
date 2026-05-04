package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.AuthTokens;
import com.nuwandev.reqflowapi.identity.application.port.input.LoginCommand;
import com.nuwandev.reqflowapi.identity.application.port.input.LoginUseCase;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import com.nuwandev.reqflowapi.identity.application.port.output.PasswordHasherPort;
import com.nuwandev.reqflowapi.identity.application.port.output.RefreshTokenGenerator;
import com.nuwandev.reqflowapi.identity.application.port.output.TokenHasher;
import com.nuwandev.reqflowapi.identity.domain.exception.InactiveUserException;
import com.nuwandev.reqflowapi.identity.domain.exception.InvalidCredentialsException;
import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.model.User;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import com.nuwandev.reqflowapi.identity.domain.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class LoginService implements LoginUseCase {

    private final UserRepository userRepository;
    private final AuthSessionRepository authSessionRepository;
    private final PasswordHasherPort passwordHasher;
    private final JwtPort jwtPort;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final TokenHasher tokenHasher;
    private final Clock clock;
    private final long refreshTokenTtlSeconds;

    public LoginService(
            UserRepository userRepository,
            AuthSessionRepository authSessionRepository,
            PasswordHasherPort passwordHasher,
            JwtPort jwtPort,
            RefreshTokenGenerator refreshTokenGenerator,
            TokenHasher tokenHasher,
            Clock clock,
            @Value("${auth.refresh-token-ttl-seconds:2592000}") long refreshTokenTtlSeconds
    ) {
        this.userRepository = userRepository;
        this.authSessionRepository = authSessionRepository;
        this.passwordHasher = passwordHasher;
        this.jwtPort = jwtPort;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.tokenHasher = tokenHasher;
        this.clock = clock;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    private static void validate(LoginCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("Login command cannot be null");
        }
        if (command.tenantId() == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (command.email() == null || command.email().isBlank()) {
            throw new IllegalArgumentException("Email cannot be null or blank");
        }
        if (command.password() == null || command.password().isBlank()) {
            throw new IllegalArgumentException("Password cannot be null or blank");
        }
    }

    @Override
    @Transactional
    public AuthTokens execute(LoginCommand command) {
        validate(command);

        User user = userRepository.findByEmail(command.tenantId(), command.email())
                .orElseThrow(() -> {
                    return new InvalidCredentialsException();
                });

        if (!user.isActive()) {
            throw new InactiveUserException();
        }
        if (!passwordHasher.matches(command.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        Instant now = Instant.now(clock);
        String rawRefreshToken = refreshTokenGenerator.generate();
        String refreshTokenHash = tokenHasher.hash(rawRefreshToken);
        AuthSession session = AuthSession.create(
                user.getId(),
                command.tenantId(),
                refreshTokenHash,
                command.ip(),
                command.userAgent(),
                now,
                now.plusSeconds(refreshTokenTtlSeconds)
        );
        authSessionRepository.save(session);

        return new AuthTokens(
                jwtPort.generateAccessToken(command.tenantId(), user, now),
                rawRefreshToken
        );
    }
}

