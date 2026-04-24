package com.nuwandev.reqflowapi.auth.domain;

import java.util.List;
import java.util.UUID;

public interface AuthSessionRepository {

    AuthSession findByRefreshTokenHash(String hash);

    void save(AuthSession session);

    void revokeAllByUserId(UUID tenantId, UUID userId);

    List<AuthSession> findAllActiveByUserId(UUID tenantId, UUID userId);
}
