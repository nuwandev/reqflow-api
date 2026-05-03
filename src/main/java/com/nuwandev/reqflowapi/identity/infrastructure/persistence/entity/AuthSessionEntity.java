package com.nuwandev.reqflowapi.identity.infrastructure.persistence.entity;

import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
public class AuthSessionEntity {
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
}
