package com.nuwandev.reqflowapi.auth.domain;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository {

    Optional<AuthSession> findByRefreshTokenHash(UUID tenantId, String hash, Instant now);

    void save(AuthSession session);

    void revokeAllByUserId(UUID tenantId, UUID userId, Instant now);

    List<AuthSession> findAllActiveByUserId(UUID tenantId, UUID userId, Instant now);
}
