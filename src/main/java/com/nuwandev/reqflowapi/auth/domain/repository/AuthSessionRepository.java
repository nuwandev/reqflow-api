package com.nuwandev.reqflowapi.auth.domain.repository;

import com.nuwandev.reqflowapi.auth.domain.model.AuthSession;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository {

    Optional<AuthSession> findById(UUID tenantId, UUID sessionId);

    Optional<AuthSession> findByRefreshTokenHashForUpdate(String hash);

    void save(AuthSession session);

    void revokeAllByUserId(UUID tenantId, UUID userId, Instant now);
}

