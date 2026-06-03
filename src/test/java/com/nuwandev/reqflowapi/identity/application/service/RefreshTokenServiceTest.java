package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.AuthTokens;
import com.nuwandev.reqflowapi.identity.application.port.input.RefreshTokenCommand;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import com.nuwandev.reqflowapi.identity.domain.port.RefreshTokenGenerator;
import com.nuwandev.reqflowapi.identity.domain.port.TokenHasher;
import com.nuwandev.reqflowapi.identity.domain.service.RefreshTokenPolicy;
import com.nuwandev.reqflowapi.identity.domain.exception.InvalidRefreshTokenException;
import com.nuwandev.reqflowapi.identity.domain.exception.RefreshTokenReuseDetectedException;
import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.model.User;
import com.nuwandev.reqflowapi.identity.domain.model.UserRole;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import com.nuwandev.reqflowapi.identity.domain.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RefreshTokenService} — all dependencies mocked.
 * Tests validate token rotation, grace-period multi-tab guard, reuse detection,
 * and tenant-scoped session lookup behaviour.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService")
class RefreshTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final long TTL_SECONDS = 2592000L;
    private static final long GRACE_PERIOD = 15L;

    @Mock private AuthSessionRepository sessionRepo;
    @Mock private UserRepository userRepo;
    @Mock private JwtPort jwtPort;
    @Mock private RefreshTokenGenerator tokenGenerator;
    @Mock private TokenHasher tokenHasher;

    private RefreshTokenService service;
    private UUID tenantId;
    private UUID userId;

    @BeforeEach
    void setUp() {
        Clock fixedClock = Clock.fixed(NOW, ZoneOffset.UTC);
        RefreshTokenPolicy policy = new RefreshTokenPolicy(GRACE_PERIOD);
        service = new RefreshTokenService(
                sessionRepo, userRepo, policy, jwtPort, tokenGenerator,
                tokenHasher, fixedClock, TTL_SECONDS
        );
        tenantId = UUID.randomUUID();
        userId = UUID.randomUUID();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Happy path — standard rotation
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("standard rotation (happy path)")
    class StandardRotation {

        @Test
        @DisplayName("should rotate an active session and return new tokens")
        void rotatesActiveSession() {
            String rawToken = "original-token";
            String hash = "original-hash";
            String newRaw = "new-token";
            String newHash = "new-hash";

            AuthSession session = buildSession(hash, false, false, null);
            User user = buildUser(true);

            when(tokenHasher.hash(rawToken)).thenReturn(hash);
            when(sessionRepo.findTenantIdByRefreshTokenHash(hash)).thenReturn(Optional.of(tenantId));
            when(sessionRepo.findByRefreshTokenHashForUpdate(hash, tenantId)).thenReturn(Optional.of(session));
            when(userRepo.findById(tenantId, userId)).thenReturn(Optional.of(user));
            when(tokenGenerator.generate()).thenReturn(newRaw);
            when(tokenHasher.hash(newRaw)).thenReturn(newHash);
            when(jwtPort.generateAccessToken(eq(tenantId), eq(user), eq(NOW))).thenReturn("access-jwt");

            AuthTokens result = service.execute(new RefreshTokenCommand(rawToken));

            assertThat(result.accessToken()).isEqualTo("access-jwt");
            assertThat(result.refreshToken()).isEqualTo(newRaw);

            // Two saves: old session rotated + new session persisted
            verify(sessionRepo, times(2)).save(any(AuthSession.class));
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Multi-tab grace period guard
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("multi-tab grace period")
    class GracePeriod {

        @Test
        @DisplayName("within grace window — should serve child session without re-rotating")
        void servesChildSessionWithinGrace() {
            String rawToken = "old-token";
            String hash = "old-hash";

            // Parent session: already rotated 5 seconds ago (within 15s grace)
            Instant rotatedAt = NOW.minusSeconds(5);
            UUID childId = UUID.randomUUID();
            AuthSession parentSession = buildRotatedSession(hash, rotatedAt, childId);

            // Child session (active)
            String childHash = "child-hash";
            AuthSession childSession = buildSession(childHash, false, false, null);
            User user = buildUser(true);

            when(tokenHasher.hash(rawToken)).thenReturn(hash);
            when(sessionRepo.findTenantIdByRefreshTokenHash(hash)).thenReturn(Optional.of(tenantId));
            when(sessionRepo.findByRefreshTokenHashForUpdate(hash, tenantId)).thenReturn(Optional.of(parentSession));
            when(sessionRepo.findById(tenantId, childId)).thenReturn(Optional.of(childSession));
            when(userRepo.findById(tenantId, userId)).thenReturn(Optional.of(user));
            when(jwtPort.generateAccessToken(eq(tenantId), eq(user), eq(NOW))).thenReturn("access-jwt");

            AuthTokens result = service.execute(new RefreshTokenCommand(rawToken));

            assertThat(result.accessToken()).isEqualTo("access-jwt");
            // Should NOT rotate again — no new session saved
            verify(sessionRepo, never()).save(any());
            // Should NOT trigger chain revocation
            verify(sessionRepo, never()).revokeSessionChain(any(), any(), any());
        }

        @Test
        @DisplayName("outside grace window — should revoke entire chain and throw")
        void revokesChainOutsideGrace() {
            String rawToken = "old-token";
            String hash = "old-hash";

            // Parent session: rotated 30 seconds ago (outside 15s grace)
            Instant rotatedAt = NOW.minusSeconds(30);
            UUID childId = UUID.randomUUID();
            AuthSession parentSession = buildRotatedSession(hash, rotatedAt, childId);

            when(tokenHasher.hash(rawToken)).thenReturn(hash);
            when(sessionRepo.findTenantIdByRefreshTokenHash(hash)).thenReturn(Optional.of(tenantId));
            when(sessionRepo.findByRefreshTokenHashForUpdate(hash, tenantId)).thenReturn(Optional.of(parentSession));

            assertThatThrownBy(() -> service.execute(new RefreshTokenCommand(rawToken)))
                    .isInstanceOf(RefreshTokenReuseDetectedException.class);

            verify(sessionRepo).revokeSessionChain(eq(tenantId), eq(parentSession.getId()), eq(NOW));
            verify(sessionRepo, never()).save(any());
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Invalid / missing sessions
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("invalid session scenarios")
    class InvalidSession {

        @Test
        @DisplayName("should throw if token not found")
        void throwsIfTokenNotFound() {
            when(tokenHasher.hash(anyString())).thenReturn("unknown-hash");
            when(sessionRepo.findTenantIdByRefreshTokenHash("unknown-hash")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.execute(new RefreshTokenCommand("bad-token")))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        }

        @Test
        @DisplayName("should throw if session is explicitly revoked (not a rotation)")
        void throwsIfExplicitlyRevoked() {
            String hash = "revoked-hash";
            // Revoked but NOT replaced (e.g. logout)
            AuthSession revokedSession = buildRevokedButNotReplacedSession(hash);

            when(tokenHasher.hash("token")).thenReturn(hash);
            when(sessionRepo.findTenantIdByRefreshTokenHash(hash)).thenReturn(Optional.of(tenantId));
            when(sessionRepo.findByRefreshTokenHashForUpdate(hash, tenantId)).thenReturn(Optional.of(revokedSession));

            assertThatThrownBy(() -> service.execute(new RefreshTokenCommand("token")))
                    .isInstanceOf(InvalidRefreshTokenException.class);

            // No chain revocation for an ordinary revoked session
            verify(sessionRepo, never()).revokeSessionChain(any(), any(), any());
        }

        @Test
        @DisplayName("should throw if session is expired")
        void throwsIfExpired() {
            String hash = "expired-hash";
            // Expired 1 second ago
            Instant expiredAt = NOW.minusSeconds(1);
            AuthSession expiredSession = AuthSession.reconstruct(
                    UUID.randomUUID(), tenantId, userId, hash,
                    null, null,
                    NOW.minusSeconds(100), expiredAt,
                    null, null, null,
                    NOW.minusSeconds(100), NOW.minusSeconds(100)
            );

            when(tokenHasher.hash("token")).thenReturn(hash);
            when(sessionRepo.findTenantIdByRefreshTokenHash(hash)).thenReturn(Optional.of(tenantId));
            when(sessionRepo.findByRefreshTokenHashForUpdate(hash, tenantId)).thenReturn(Optional.of(expiredSession));

            assertThatThrownBy(() -> service.execute(new RefreshTokenCommand("token")))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        }

        @Test
        @DisplayName("should revoke all sessions if user is inactive")
        void revokesIfUserInactive() {
            String rawToken = "active-token";
            String hash = "active-hash";
            AuthSession session = buildSession(hash, false, false, null);
            User inactiveUser = buildUser(false);

            when(tokenHasher.hash(rawToken)).thenReturn(hash);
            when(sessionRepo.findTenantIdByRefreshTokenHash(hash)).thenReturn(Optional.of(tenantId));
            when(sessionRepo.findByRefreshTokenHashForUpdate(hash, tenantId)).thenReturn(Optional.of(session));
            when(userRepo.findById(tenantId, userId)).thenReturn(Optional.of(inactiveUser));

            assertThatThrownBy(() -> service.execute(new RefreshTokenCommand(rawToken)))
                    .isInstanceOf(com.nuwandev.reqflowapi.identity.domain.exception.InactiveUserException.class);

            verify(sessionRepo).revokeAllByUserId(eq(tenantId), eq(userId), eq(NOW));
        }

        @Test
        @DisplayName("should throw if refresh token command is null")
        void throwsOnNullCommand() {
            assertThatThrownBy(() -> service.execute(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private AuthSession buildSession(String hash, boolean revoked, boolean replaced, UUID replacedById) {
        Instant revokedAt = revoked ? NOW : null;
        return AuthSession.reconstruct(
                UUID.randomUUID(), tenantId, userId, hash,
                "127.0.0.1", "Agent/1.0",
                NOW.minusSeconds(60), NOW.plusSeconds(TTL_SECONDS),
                revokedAt, replacedById, null,
                NOW.minusSeconds(60), NOW.minusSeconds(60)
        );
    }

    private AuthSession buildRotatedSession(String hash, Instant rotatedAt, UUID childId) {
        // Rotated = revoked + replaced
        return AuthSession.reconstruct(
                UUID.randomUUID(), tenantId, userId, hash,
                "127.0.0.1", "Agent/1.0",
                NOW.minusSeconds(60), NOW.plusSeconds(TTL_SECONDS),
                rotatedAt,        // revokedAt = same as rotatedAt
                childId,          // replacedBySessionId
                rotatedAt,        // rotatedAt
                NOW.minusSeconds(60), rotatedAt
        );
    }

    private AuthSession buildRevokedButNotReplacedSession(String hash) {
        return AuthSession.reconstruct(
                UUID.randomUUID(), tenantId, userId, hash,
                null, null,
                NOW.minusSeconds(60), NOW.plusSeconds(TTL_SECONDS),
                NOW.minusSeconds(10),  // revokedAt — explicitly revoked
                null,                  // replacedBySessionId = null → NOT a rotation
                null,                  // rotatedAt = null
                NOW.minusSeconds(60), NOW.minusSeconds(10)
        );
    }

    private User buildUser(boolean active) {
        User user = User.reconstruct(
                userId, tenantId,
                "user@example.com", "hashed-password",
                "Test User", UserRole.REQUESTOR,
                active,
                NOW.minusSeconds(100), NOW.minusSeconds(100)
        );
        return user;
    }
}
