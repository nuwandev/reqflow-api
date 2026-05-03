package com.nuwandev.reqflowapi.identity.domain.repository;

import com.nuwandev.reqflowapi.identity.domain.model.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository {

    Optional<User> findByEmail(UUID tenantId, String email);

    Optional<User> findById(UUID tenantId, UUID userId);

    void save(User user);
}

