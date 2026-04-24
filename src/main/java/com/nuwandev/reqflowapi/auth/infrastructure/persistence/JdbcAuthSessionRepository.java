package com.nuwandev.reqflowapi.auth.infrastructure.persistence;

import com.nuwandev.reqflowapi.auth.domain.AuthSession;
import com.nuwandev.reqflowapi.auth.domain.AuthSessionRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class JdbcAuthSessionRepository implements AuthSessionRepository {
    @Override
    public Optional<AuthSession> findByRefreshTokenHash(String hash) {
        return Optional.empty();
    }

    @Override
    public void save(AuthSession session) {

    }

    @Override
    public void revokeAllByUserId(UUID tenantId, UUID userId) {

    }

    @Override
    public Optional<List<AuthSession>> findAllActiveByUserId(UUID tenantId, UUID userId) {
        return Optional.empty();
    }
}
