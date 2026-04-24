package com.nuwandev.reqflowapi.auth.domain;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository {

    Optional<AuthSession> findByRefreshTokenHash(String hash);

    void save(AuthSession session);

    void revokeAllByUserId(UUID tenantId, UUID userId);

    Optional<List<AuthSession>> findAllActiveByUserId(UUID tenantId, UUID userId);
}
