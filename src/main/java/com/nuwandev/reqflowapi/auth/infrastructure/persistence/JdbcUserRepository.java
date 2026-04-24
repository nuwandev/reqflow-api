package com.nuwandev.reqflowapi.auth.infrastructure.persistence;

import com.nuwandev.reqflowapi.auth.domain.User;
import com.nuwandev.reqflowapi.auth.domain.UserRepository;

import java.util.Optional;
import java.util.UUID;

public class JdbcUserRepository implements UserRepository {
    @Override
    public Optional<User> findByEmail(UUID tenantId, String email) {
        return Optional.empty();
    }

    @Override
    public Optional<User> findById(UUID tenantId, UUID userId) {
        return Optional.empty();
    }

    @Override
    public void save(User user) {

    }
}
