package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.AuthTokens;
import com.nuwandev.reqflowapi.identity.application.port.input.RefreshTokenCommand;
import com.nuwandev.reqflowapi.identity.application.port.input.RefreshTokenUseCase;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import com.nuwandev.reqflowapi.identity.domain.port.RefreshTokenGenerator;
import com.nuwandev.reqflowapi.identity.domain.port.TokenHasher;
import com.nuwandev.reqflowapi.identity.domain.service.RefreshTokenPolicy;
import com.nuwandev.reqflowapi.identity.domain.exception.InactiveUserException;
import com.nuwandev.reqflowapi.identity.domain.exception.InvalidRefreshTokenException;
import com.nuwandev.reqflowapi.identity.domain.exception.RefreshTokenReuseDetectedException;
import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.model.User;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import com.nuwandev.reqflowapi.identity.domain.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService implements RefreshTokenUseCase {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final AuthSessionRepository authSessionRepository;
    private final UserRepository userRepository;
    private final RefreshTokenPolicy refreshTokenPolicy;
    private final JwtPort jwtPort;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final TokenHasher tokenHasher;
    private final Clock clock;
    private final long refreshTokenTtlSeconds;

    public RefreshTokenService(
            AuthSessionRepository authSessionRepository,
            UserRepository userRepository,
            RefreshTokenPolicy refreshTokenPolicy,
            JwtPort jwtPort,
            RefreshTokenGenerator refreshTokenGenerator,
            TokenHasher tokenHasher,
            Clock clock,
            @Value("${auth.refresh-token-ttl-seconds:2592000}") long refreshTokenTtlSeconds
    ) {
        this.authSessionRepository = authSessionRepository;
        this.userRepository = userRepository;
        this.refreshTokenPolicy = refreshTokenPolicy;
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

    @Override
    @Transactional
    public AuthTokens execute(RefreshTokenCommand command) {
        validate(command);

        Instant now = Instant.now(clock);
        String refreshTokenHash = tokenHasher.hash(command.refreshToken());

        // ── Phase 1: lightweight tenant discovery (no lock)
        // We must know the tenant_id before we can issue the tenant-scoped FOR UPDATE
        // query. The token itself carries no embedded tenant — the canonical source of
        // truth is the database row.
        UUID tenantId = authSessionRepository
                .findTenantIdByRefreshTokenHash(refreshTokenHash)
                .orElseThrow(InvalidRefreshTokenException::new);

        // ── Phase 2: tenant-scoped fetch under a pessimistic write-lock
        // The composite (refresh_token_hash, tenant_id) predicate enforces strict
        // cross-tenant isolation at the database level.
        AuthSession session = authSessionRepository
                .findByRefreshTokenHashForUpdate(refreshTokenHash, tenantId)
                .orElseThrow(InvalidRefreshTokenException::new);

        // ── Guard 1: Revoked session (explicit revocation, not rotation)
        if (session.isRevoked() && !session.wasReplaced()) {
            throw new InvalidRefreshTokenException();
        }

        // ── Guard 2: Multi-tab race-condition grace period
        // A session that is both revoked AND replaced is a "reuse attempt". We
        // distinguish between a benign concurrent-tab replay (within the grace window)
        // and a genuine adversarial token replay (outside the grace window).
        if (session.isReuseAttempt()) {
            if (refreshTokenPolicy.isWithinGracePeriod(session, now)) {
                log.debug("Token reuse within rotation grace window — serving child session for tenant={}",
                        tenantId);

                // Serve the already-issued child session's access token.
                // The client already holds the new refresh token from the first successful
                // rotation; we do NOT rotate again to avoid invalidating the first tab.
                AuthSession childSession = authSessionRepository
                        .findById(tenantId, session.getReplacedBySessionId())
                        .orElseThrow(InvalidRefreshTokenException::new);

                User childUser = userRepository
                        .findById(tenantId, childSession.getUserId())
                        .orElseThrow(InvalidRefreshTokenException::new);

                try {
                    refreshTokenPolicy.validateUserCanRefresh(childUser);
                } catch (InactiveUserException e) {
                    authSessionRepository.revokeAllByUserId(tenantId, childUser.getId(), now);
                    throw e;
                }

                return new AuthTokens(
                        jwtPort.generateAccessToken(tenantId, childUser, now),
                        // The child session's raw token is unknown here (hashed-only storage).
                        // The client MUST use the refresh token returned from the first rotation.
                        // We signal this by returning the *original* token so the client keeps
                        // retrying the same cookie — the next call will hit the child session directly.
                        command.refreshToken()
                );
            }

            // Outside the grace window: genuine adversarial reuse — revoke the full chain.
            log.warn("Refresh token reuse anomaly outside grace window — revoking full chain: " +
                    "tenant={} ancestralSession={}", tenantId, session.getId());
            authSessionRepository.revokeSessionChain(tenantId, session.getId(), now);
            throw new RefreshTokenReuseDetectedException();
        }

        // ── Guard 3: Reject expired or otherwise non-refreshable sessions
        if (!session.canBeUsedForRefresh(now)) {
            throw new InvalidRefreshTokenException();
        }

        // ── Step 3: Verify owner identity and account status
        User user = userRepository.findById(tenantId, session.getUserId())
                .orElseThrow(InvalidRefreshTokenException::new);

        try {
            refreshTokenPolicy.validateUserCanRefresh(user);
        } catch (InactiveUserException e) {
            authSessionRepository.revokeAllByUserId(tenantId, user.getId(), now);
            throw e;
        }

        // ── Step 4: Issue new session (standard rotation)
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
