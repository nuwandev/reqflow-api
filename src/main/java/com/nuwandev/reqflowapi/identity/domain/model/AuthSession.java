package com.nuwandev.reqflowapi.identity.domain.model;

import java.time.Instant;
import java.util.UUID;

public class AuthSession {
    private UUID id;
    private UUID tenantId;
    private UUID userId;
    private String refreshTokenHash;
    private String ipAddress;
    private String userAgent;
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
            String ipAddress,
            String userAgent,
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
        session.ipAddress = normalizeOptional(ipAddress);
        session.userAgent = normalizeOptional(userAgent);
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
            String ipAddress,
            String userAgent,
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
        if (expiresAt.isBefore(issuedAt))
            throw new IllegalStateException("Invalid session: expires before issued");
        if (createdAt == null)
            throw new IllegalArgumentException("createdAt cannot be null");
        if (updatedAt == null)
            throw new IllegalArgumentException("updatedAt cannot be null");

        AuthSession session = new AuthSession();
        session.id = id;
        session.tenantId = tenantId;
        session.userId = userId;
        session.refreshTokenHash = refreshTokenHash;
        session.ipAddress = normalizeOptional(ipAddress);
        session.userAgent = normalizeOptional(userAgent);
        session.issuedAt = issuedAt;
        session.expiresAt = expiresAt;
        session.revokedAt = revokedAt;
        session.replacedBySessionId = replacedBySessionId;
        session.createdAt = createdAt;
        session.updatedAt = updatedAt;

        return session;
    }

    private static void requireNow(Instant now) {
        if (now == null)
            throw new IllegalArgumentException("Now cannot be null");
    }

    private static String normalizeOptional(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isBlank() ? null : normalized;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getRefreshTokenHash() {
        return refreshTokenHash;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public UUID getReplacedBySessionId() {
        return replacedBySessionId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
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
}

