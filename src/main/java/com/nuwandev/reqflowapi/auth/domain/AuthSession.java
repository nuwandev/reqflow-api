package com.nuwandev.reqflowapi.auth.domain;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;

public class AuthSession {
    private UUID id;
    private UUID tenantId;
    private UUID userId;

    private Instant issuedAt;
    private Instant expiresAt;
    private Instant revokedAt;

    private String refreshTokenHash;

    private UUID replacedBySessionId;

    public static AuthSession create(
            UUID userId,
            UUID tenantId,
            String refreshTokenHash,
            Instant now,
            Instant expiry
    ) {
        if (userId == null)
            throw new IllegalArgumentException("User ID cannot be null");
        if (tenantId == null)
            throw new IllegalArgumentException("Tenant ID cannot be null");
        if (refreshTokenHash == null || refreshTokenHash.isBlank())
            throw new IllegalArgumentException("Refresh token hash cannot be null or blank");
        if (now == null)
            throw new IllegalArgumentException("Current time cannot be null");
        if (expiry == null)
            throw new IllegalArgumentException("Expiry time cannot be null");
        if (expiry.isBefore(now))
            throw new IllegalArgumentException("Expiry time must be in the future");

        AuthSession session = new AuthSession();
        session.id = UUID.randomUUID();
        session.userId = userId;
        session.tenantId = tenantId;
        session.refreshTokenHash = refreshTokenHash;
        session.issuedAt = now;
        session.expiresAt = expiry;

        return session;
    }

    public boolean canBeUsedForRefresh(Instant now) {
        return !isRevoked() && !wasReplaced() && !isExpired(now);
    }

    public boolean isExpired(Instant now) {
        return this.expiresAt.isBefore(now);
    }

    public boolean isRevoked() {
        return this.revokedAt != null;
    }

    public void revoke(Instant time) {
        if (revokedAt != null)
            throw new IllegalStateException("Session is already revoked");

        this.revokedAt = time;
    }

    public void markReplacedBy(UUID newSessionId) {
        if (replacedBySessionId != null)
            throw new IllegalStateException("Session is already replaced by another session");

        this.replacedBySessionId = newSessionId;
        if (this.revokedAt == null) {
            this.revokedAt = Instant.now();
        }
    }

    public boolean matchesToken(String hash) {
        if (hash == null || hash.isBlank())
            throw new IllegalArgumentException("Input token hash is null or blank");
        if (refreshTokenHash == null)
            throw new IllegalStateException("Session does not have a refresh token hash");

        return MessageDigest.isEqual(hash.getBytes(), this.refreshTokenHash.getBytes());
    }

    public boolean isReuseAttempt() {
        return isRevoked();
    }

    public boolean wasReplaced() {
        return replacedBySessionId != null;
    }
}
