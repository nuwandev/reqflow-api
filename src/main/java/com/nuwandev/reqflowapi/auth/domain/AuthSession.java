package com.nuwandev.reqflowapi.auth.domain;

import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;

@Getter
public class AuthSession {
    private UUID id;
    private UUID tenantId;
    private UUID userId;
    private String refreshTokenHash;
    private Instant issuedAt;
    private Instant expiresAt;
    private Instant revokedAt;
    private UUID replacedBySessionId;
    private Instant createdAt;
    private Instant updatedAt;

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
        session.createdAt = now;
        session.updatedAt = now;

        return session;
    }

    public static AuthSession reconstruct(
            UUID id,
            UUID tenantId,
            UUID userId,
            String refreshTokenHash,
            Instant issuedAt,
            Instant expiresAt,
            Instant revokedAt,
            UUID replacedBySessionId,
            Instant createdAt,
            Instant updatedAt
    ) {
        if (id == null)
            throw new IllegalArgumentException("Session ID cannot be null");
        if (tenantId == null)
            throw new IllegalArgumentException("Tenant ID cannot be null");
        if (userId == null)
            throw new IllegalArgumentException("User ID cannot be null");
        if (refreshTokenHash == null || refreshTokenHash.isBlank())
            throw new IllegalArgumentException("Refresh token hash cannot be null or blank");
        if (issuedAt == null)
            throw new IllegalArgumentException("issuedAt cannot be null");
        if (expiresAt == null)
            throw new IllegalArgumentException("expiresAt cannot be null");
        if (createdAt == null)
            throw new IllegalArgumentException("createdAt cannot be null");
        if (updatedAt == null)
            throw new IllegalArgumentException("updatedAt cannot be null");

        AuthSession session = new AuthSession();
        session.id = id;
        session.tenantId = tenantId;
        session.userId = userId;
        session.refreshTokenHash = refreshTokenHash;
        session.issuedAt = issuedAt;
        session.expiresAt = expiresAt;
        session.revokedAt = revokedAt;
        session.replacedBySessionId = replacedBySessionId;
        session.createdAt = createdAt;
        session.updatedAt = updatedAt;

        return session;
    }

    public boolean canBeUsedForRefresh(Instant now) {
        requireNow(now);
        return !isRevoked() && !wasReplaced() && !isExpired(now);
    }

    public boolean isExpired(Instant now) {
        requireNow(now);
        return this.expiresAt.isBefore(now);
    }

    public boolean isRevoked() {
        return this.revokedAt != null;
    }

    public void revoke(Instant now) {
        requireNow(now);
        if (revokedAt != null)
            throw new IllegalStateException("Session is already revoked");

        this.revokedAt = now;
        this.updatedAt = now;
    }

    public void rotate(UUID newSessionId, Instant now) {
        requireNow(now);
        if (isRevoked())
            throw new IllegalStateException("Cannot rotate a revoked session");
        if (newSessionId == null)
            throw new IllegalArgumentException("Replacement session ID cannot be null");
        if (newSessionId.equals(this.id))
            throw new IllegalArgumentException("Replacement session ID cannot be the same as the current session ID");
        if (replacedBySessionId != null)
            throw new IllegalStateException("Session is already replaced by another session");

        this.replacedBySessionId = newSessionId;
        this.revokedAt = now;
        this.updatedAt = now;
    }

    public boolean isReuseAttempt() {
        return isRevoked() && wasReplaced();
    }

    public boolean wasReplaced() {
        return replacedBySessionId != null;
    }

    private static void requireNow(Instant now) {
        if (now == null)
            throw new IllegalArgumentException("Now cannot be null");
    }
}
