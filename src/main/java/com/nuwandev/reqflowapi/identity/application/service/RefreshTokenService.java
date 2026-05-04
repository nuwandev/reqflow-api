package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.AuthTokens;
import com.nuwandev.reqflowapi.identity.application.port.input.RefreshTokenCommand;
import com.nuwandev.reqflowapi.identity.application.port.input.RefreshTokenUseCase;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import com.nuwandev.reqflowapi.identity.application.port.output.RefreshTokenGenerator;
import com.nuwandev.reqflowapi.identity.application.port.output.TokenHasher;
import com.nuwandev.reqflowapi.identity.domain.exception.InactiveUserException;
import com.nuwandev.reqflowapi.identity.domain.exception.InvalidRefreshTokenException;
import com.nuwandev.reqflowapi.identity.domain.exception.RefreshTokenReuseDetectedException;
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
public class RefreshTokenService implements RefreshTokenUseCase {

    private final AuthSessionRepository authSessionRepository;
    private final UserRepository userRepository;
    private final JwtPort jwtPort;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final TokenHasher tokenHasher;
    private final Clock clock;
    private final long refreshTokenTtlSeconds;

    public RefreshTokenService(
            AuthSessionRepository authSessionRepository,
            UserRepository userRepository,
            JwtPort jwtPort,
            RefreshTokenGenerator refreshTokenGenerator,
            TokenHasher tokenHasher,
            Clock clock,
            @Value("${auth.refresh-token-ttl-seconds:2592000}") long refreshTokenTtlSeconds
    ) {
        this.authSessionRepository = authSessionRepository;
        this.userRepository = userRepository;
        this.jwtPort = jwtPort;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.tokenHasher = tokenHasher;
        this.clock = clock;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    private static void validate(RefreshTokenCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("Refresh token command cannot be null");
        }
        if (command.refreshToken() == null || command.refreshToken().isBlank()) {
            throw new IllegalArgumentException("Refresh token cannot be null or blank");
        }
    }

    private void revokeSessionChain(java.util.UUID tenantId, AuthSession reusedSession, Instant now) {
        AuthSession current = reusedSession;

        while (current.getReplacedBySessionId() != null) {
            current = authSessionRepository.findById(tenantId, current.getReplacedBySessionId())
                    .orElseThrow(() -> new IllegalStateException("Broken auth session chain"));

            if (!current.isRevoked()) {
                current.revoke(now);
                authSessionRepository.save(current);
            }
        }
    }

    @Override
    @Transactional
    public AuthTokens execute(RefreshTokenCommand command) {
        validate(command);

        Instant now = Instant.now(clock);
        String refreshTokenHash = tokenHasher.hash(command.refreshToken());

        AuthSession session = authSessionRepository.findByRefreshTokenHashForUpdate(refreshTokenHash)
                .orElseThrow(InvalidRefreshTokenException::new);
        java.util.UUID tenantId = session.getTenantId();

        if (!session.canBeUsedForRefresh(now)) {
            if (session.isReuseAttempt()) {
                revokeSessionChain(tenantId, session, now);
                throw new RefreshTokenReuseDetectedException();
            }
            throw new InvalidRefreshTokenException();
        }

        User user = userRepository.findById(tenantId, session.getUserId())
                .orElseThrow(InvalidRefreshTokenException::new);

        if (!user.isActive()) {
            authSessionRepository.revokeAllByUserId(tenantId, user.getId(), now);
            throw new InactiveUserException();
        }

        String newRawRefreshToken = refreshTokenGenerator.generate();
        String newRefreshTokenHash = tokenHasher.hash(newRawRefreshToken);
        AuthSession newSession = AuthSession.create(
                user.getId(),
                tenantId,
                newRefreshTokenHash,
                session.getIpAddress(),
                session.getUserAgent(),
                now,
                now.plusSeconds(refreshTokenTtlSeconds)
        );

        session.rotate(newSession.getId(), now);
        authSessionRepository.save(session);
        authSessionRepository.save(newSession);

        return new AuthTokens(
                jwtPort.generateAccessToken(tenantId, user, now),
                newRawRefreshToken
        );
    }
}

