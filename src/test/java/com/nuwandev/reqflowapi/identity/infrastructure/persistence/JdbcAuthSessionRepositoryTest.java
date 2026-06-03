package com.nuwandev.reqflowapi.identity.infrastructure.persistence;

import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.model.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class JdbcAuthSessionRepositoryTest {

    @Autowired
    private JdbcAuthSessionRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UUID tenantId;
    private UUID userId;
    private Instant now;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        userId = UUID.randomUUID();
        now = Instant.now();

        // Insert reference tenant and user to satisfy FK constraints
        jdbcTemplate.update(
                "INSERT INTO tenants (id, slug, name, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                tenantId, "test-tenant-" + tenantId, "Test Tenant", true, now, now
        );

        jdbcTemplate.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, full_name, role, team_id, is_active, row_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                userId, tenantId, "test@example.com", "hash", "Test User", UserRole.REQUESTOR.name(), null, true, 0L, now, now
        );
    }

    @Test
    @DisplayName("Should save and find a session by ID")
    void testSaveAndFindById() {
        UUID sessionId = UUID.randomUUID();
        AuthSession session = AuthSession.reconstruct(
                sessionId, tenantId, userId, "hash123", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        );

        repository.save(session);

        Optional<AuthSession> retrieved = repository.findById(tenantId, sessionId);
        assertThat(retrieved).isPresent();
        assertThat(retrieved.get().getId()).isEqualTo(sessionId);
        assertThat(retrieved.get().getRefreshTokenHash()).isEqualTo("hash123");
    }

    @Test
    @DisplayName("Should find tenant ID by refresh token hash")
    void testFindTenantIdByRefreshTokenHash() {
        UUID sessionId = UUID.randomUUID();
        AuthSession session = AuthSession.reconstruct(
                sessionId, tenantId, userId, "hash-lookup", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        );
        repository.save(session);

        Optional<UUID> foundTenantId = repository.findTenantIdByRefreshTokenHash("hash-lookup");
        assertThat(foundTenantId).isPresent().contains(tenantId);

        Optional<UUID> notFound = repository.findTenantIdByRefreshTokenHash("non-existent");
        assertThat(notFound).isEmpty();
    }

    @Test
    @DisplayName("Should find session by hash and tenant ID for update")
    void testFindByRefreshTokenHashForUpdate() {
        UUID sessionId = UUID.randomUUID();
        AuthSession session = AuthSession.reconstruct(
                sessionId, tenantId, userId, "hash-for-update", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        );
        repository.save(session);

        // Matches both hash and tenant ID
        Optional<AuthSession> found = repository.findByRefreshTokenHashForUpdate("hash-for-update", tenantId);
        assertThat(found).isPresent();

        // Mismatched tenant ID should not find the session (cross-tenant isolation)
        UUID otherTenantId = UUID.randomUUID();
        Optional<AuthSession> crossTenantFound = repository.findByRefreshTokenHashForUpdate("hash-for-update", otherTenantId);
        assertThat(crossTenantFound).isEmpty();
    }

    @Test
    @DisplayName("Should update existing session on conflict (upsert)")
    void testUpsertSession() {
        UUID sessionId = UUID.randomUUID();
        AuthSession session = AuthSession.reconstruct(
                sessionId, tenantId, userId, "hash-upsert", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        );
        repository.save(session);

        // Save successor first to satisfy FK constraint
        UUID successorId = UUID.randomUUID();
        AuthSession successor = AuthSession.reconstruct(
                successorId, tenantId, userId, "successor-hash", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        );
        repository.save(successor);

        // Update the session: rotate it
        AuthSession updatedSession = AuthSession.reconstruct(
                sessionId, tenantId, userId, "hash-upsert", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), now, successorId, now, now, now
        );
        repository.save(updatedSession);

        Optional<AuthSession> retrieved = repository.findById(tenantId, sessionId);
        assertThat(retrieved).isPresent();
        assertThat(retrieved.get().getRevokedAt()).isNotNull();
        assertThat(retrieved.get().getReplacedBySessionId()).isEqualTo(successorId);
        assertThat(retrieved.get().getRotatedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should revoke all active sessions for a user")
    void testRevokeAllByUserId() {
        UUID s1 = UUID.randomUUID();
        UUID s2 = UUID.randomUUID();

        repository.save(AuthSession.reconstruct(
                s1, tenantId, userId, "hash-s1", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        ));
        repository.save(AuthSession.reconstruct(
                s2, tenantId, userId, "hash-s2", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        ));

        repository.revokeAllByUserId(tenantId, userId, now);

        assertThat(repository.findById(tenantId, s1).get().getRevokedAt()).isNotNull();
        assertThat(repository.findById(tenantId, s2).get().getRevokedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should recursively revoke session chain via CTE")
    void testRevokeSessionChain() {
        UUID s1 = UUID.randomUUID();
        UUID s2 = UUID.randomUUID();
        UUID s3 = UUID.randomUUID();

        // Setup parent-child chain: s1 -> s2 -> s3
        // To satisfy referential integrity, we insert in reverse order: s3, then s2, then s1.
        // S3 is active
        repository.save(AuthSession.reconstruct(
                s3, tenantId, userId, "hash-s3", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        ));
        // S2 rotated into S3
        repository.save(AuthSession.reconstruct(
                s2, tenantId, userId, "hash-s2", "127.0.0.1", "Agent",
                now.minusSeconds(50), now.plusSeconds(3600), now.minusSeconds(10), s3, now.minusSeconds(10), now, now
        ));
        // S1 rotated into S2
        repository.save(AuthSession.reconstruct(
                s1, tenantId, userId, "hash-s1", "127.0.0.1", "Agent",
                now.minusSeconds(100), now.plusSeconds(3600), now.minusSeconds(50), s2, now.minusSeconds(50), now, now
        ));

        // Revoking ancestral chain starting from s1
        repository.revokeSessionChain(tenantId, s1, now);

        // s1 and s2 were already rotated/revoked, but s3 should now be revoked by the CTE walk!
        assertThat(repository.findById(tenantId, s3).get().getRevokedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should purge expired or long-revoked sessions")
    void testPurgeExpiredAndRevoked() {
        UUID expiredId = UUID.randomUUID();
        UUID revokedId = UUID.randomUUID();
        UUID activeId = UUID.randomUUID();

        // 1. Expired session (expires_at in the past)
        repository.save(AuthSession.reconstruct(
                expiredId, tenantId, userId, "expired", "127.0.0.1", "Agent",
                now.minusSeconds(100), now.minusSeconds(10), null, null, null, now, now
        ));

        // 2. Revoked session (revoked_at > 10 days ago, retention is 7 days)
        Instant longAgo = now.minusSeconds(3600 * 24 * 10);
        repository.save(AuthSession.reconstruct(
                revokedId, tenantId, userId, "revoked-old", "127.0.0.1", "Agent",
                longAgo, now.plusSeconds(3600), longAgo, null, null, now, now
        ));

        // 3. Active session (expires in future, not revoked)
        repository.save(AuthSession.reconstruct(
                activeId, tenantId, userId, "active", "127.0.0.1", "Agent",
                now, now.plusSeconds(3600), null, null, null, now, now
        ));

        // Run purge with 7 days retention
        int deletedCount = repository.purgeExpiredAndRevoked(now, 7);

        assertThat(deletedCount).isEqualTo(2);
        assertThat(repository.findById(tenantId, expiredId)).isEmpty();
        assertThat(repository.findById(tenantId, revokedId)).isEmpty();
        assertThat(repository.findById(tenantId, activeId)).isPresent();
    }
}
