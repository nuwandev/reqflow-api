package com.nuwandev.reqflowapi.identity.domain.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Pure unit tests for {@link AuthSession} domain model.
 * No Spring context — fast, isolated, and deterministic.
 */
@DisplayName("AuthSession domain model")
class AuthSessionTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final Instant FUTURE = NOW.plusSeconds(2592000);
    private static final Instant PAST = NOW.minusSeconds(1);

    private AuthSession newActiveSession() {
        return AuthSession.create(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "sha256-hash-value",
                "127.0.0.1",
                "TestAgent/1.0",
                NOW,
                FUTURE
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // create()
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("create()")
    class Create {

        @Test
        @DisplayName("should produce an active, non-expired, non-revoked session")
        void createsValidSession() {
            AuthSession session = newActiveSession();
            assertThat(session.getId()).isNotNull();
            assertThat(session.isRevoked()).isFalse();
            assertThat(session.wasReplaced()).isFalse();
            assertThat(session.isExpired(NOW)).isFalse();
            assertThat(session.canBeUsedForRefresh(NOW)).isTrue();
            assertThat(session.getRotatedAt()).isNull();
        }

        @Test
        @DisplayName("should reject null userId")
        void rejectsNullUserId() {
            assertThatThrownBy(() -> AuthSession.create(null, UUID.randomUUID(), "hash", null, null, NOW, FUTURE))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("should reject null tenantId")
        void rejectsNullTenantId() {
            assertThatThrownBy(() -> AuthSession.create(UUID.randomUUID(), null, "hash", null, null, NOW, FUTURE))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("should reject expiry before now")
        void rejectsExpiryBeforeNow() {
            assertThatThrownBy(() -> AuthSession.create(UUID.randomUUID(), UUID.randomUUID(), "hash", null, null, NOW, PAST))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // rotate()
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("rotate()")
    class Rotate {

        @Test
        @DisplayName("should mark session as replaced and set rotatedAt")
        void setsRotatedAt() {
            AuthSession session = newActiveSession();
            UUID newId = UUID.randomUUID();

            session.rotate(newId, NOW);

            assertThat(session.wasReplaced()).isTrue();
            assertThat(session.getReplacedBySessionId()).isEqualTo(newId);
            assertThat(session.getRotatedAt()).isEqualTo(NOW);
            assertThat(session.isRevoked()).isTrue();      // rotation simultaneously revokes
            assertThat(session.getRevokedAt()).isEqualTo(NOW);
        }

        @Test
        @DisplayName("should throw if already revoked")
        void throwsIfAlreadyRevoked() {
            AuthSession session = newActiveSession();
            session.revoke(NOW);
            assertThatThrownBy(() -> session.rotate(UUID.randomUUID(), NOW))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("should throw if already replaced")
        void throwsIfAlreadyReplaced() {
            AuthSession session = newActiveSession();
            session.rotate(UUID.randomUUID(), NOW);
            assertThatThrownBy(() -> session.rotate(UUID.randomUUID(), NOW))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // isWithinRotationGracePeriod()
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("isWithinRotationGracePeriod()")
    class GracePeriod {

        @Test
        @DisplayName("should return true when rotated_at is within the grace window")
        void trueWithinGrace() {
            AuthSession session = newActiveSession();
            session.rotate(UUID.randomUUID(), NOW);
            // Check 10 seconds after rotation — within the 15 second grace window
            Instant tenSecondsLater = NOW.plusSeconds(10);
            assertThat(session.isWithinRotationGracePeriod(tenSecondsLater, 15)).isTrue();
        }

        @Test
        @DisplayName("should return false when rotated_at is outside the grace window")
        void falseOutsideGrace() {
            AuthSession session = newActiveSession();
            session.rotate(UUID.randomUUID(), NOW);
            // Check 30 seconds after rotation — well outside the 15 second grace window
            Instant thirtySecondsLater = NOW.plusSeconds(30);
            assertThat(session.isWithinRotationGracePeriod(thirtySecondsLater, 15)).isFalse();
        }

        @Test
        @DisplayName("should return false when session has never been rotated")
        void falseWhenNeverRotated() {
            AuthSession session = newActiveSession();
            assertThat(session.isWithinRotationGracePeriod(NOW, 15)).isFalse();
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // isReuseAttempt()
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("isReuseAttempt()")
    class ReuseAttempt {

        @Test
        @DisplayName("returns true only when session is both revoked AND replaced")
        void trueWhenRevokedAndReplaced() {
            AuthSession session = newActiveSession();
            session.rotate(UUID.randomUUID(), NOW);
            assertThat(session.isReuseAttempt()).isTrue();
        }

        @Test
        @DisplayName("returns false when session is revoked but not replaced (explicit logout)")
        void falseWhenRevokedNotReplaced() {
            AuthSession session = newActiveSession();
            session.revoke(NOW);
            assertThat(session.isReuseAttempt()).isFalse();
        }

        @Test
        @DisplayName("returns false when session is active")
        void falseWhenActive() {
            AuthSession session = newActiveSession();
            assertThat(session.isReuseAttempt()).isFalse();
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // canBeUsedForRefresh()
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("canBeUsedForRefresh()")
    class CanBeUsedForRefresh {

        @Test
        @DisplayName("returns true for a fresh, non-expired active session")
        void trueForFreshSession() {
            assertThat(newActiveSession().canBeUsedForRefresh(NOW)).isTrue();
        }

        @Test
        @DisplayName("returns false after explicit revocation")
        void falseAfterRevoke() {
            AuthSession session = newActiveSession();
            session.revoke(NOW);
            assertThat(session.canBeUsedForRefresh(NOW)).isFalse();
        }

        @Test
        @DisplayName("returns false after rotation (replaced)")
        void falseAfterRotation() {
            AuthSession session = newActiveSession();
            session.rotate(UUID.randomUUID(), NOW);
            assertThat(session.canBeUsedForRefresh(NOW)).isFalse();
        }

        @Test
        @DisplayName("returns false when expired")
        void falseWhenExpired() {
            AuthSession session = newActiveSession();
            Instant afterExpiry = FUTURE.plusSeconds(1);
            assertThat(session.canBeUsedForRefresh(afterExpiry)).isFalse();
        }
    }
}
