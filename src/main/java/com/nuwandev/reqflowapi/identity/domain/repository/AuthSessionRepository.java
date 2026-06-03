package com.nuwandev.reqflowapi.identity.domain.repository;

import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository {

    Optional<AuthSession> findById(UUID tenantId, UUID sessionId);

    /**
     * Acquires a pessimistic write-lock on the matching row and returns the session
     * only when <em>both</em> the token hash and the tenant context match.
     * This enforces strict database-level tenant isolation: a session cannot be
     * fetched or mutated outside its verified tenant workspace.
     */
    Optional<AuthSession> findByRefreshTokenHashForUpdate(String hash, UUID tenantId);

    void save(AuthSession session);

    void revokeAllByUserId(UUID tenantId, UUID userId, Instant now);

    /**
     * Revokes every session in the forward replacement chain starting from
     * {@code ancestralSessionId}. Used during reuse-detection to invalidate
     * all descendant tokens in one operation.
     */
    void revokeSessionChain(UUID tenantId, UUID ancestralSessionId, Instant now);

    /**
     * Background cleanup: deletes rows whose TTL has elapsed or that were revoked
     * more than {@code revokedRetentionDays} days ago.
     *
     * @return number of rows deleted
     */
    int purgeExpiredAndRevoked(Instant now, int revokedRetentionDays);

    /**
     * Minimal projection query: returns only the {@code tenant_id} for the given
     * token hash without acquiring a row lock. Used as the first phase of the
     * two-phase tenant-scoped lookup in {@code RefreshTokenService} so that the
     * full tenant-isolated {@link #findByRefreshTokenHashForUpdate} can be called
     * with the correct tenant context.
     */
    Optional<UUID> findTenantIdByRefreshTokenHash(String hash);
}

