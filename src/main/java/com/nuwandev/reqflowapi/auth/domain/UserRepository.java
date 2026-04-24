package com.nuwandev.reqflowapi.auth.domain;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository {

    Optional<User> findByEmail(UUID tenantId, String email);

    Optional<User> findById(UUID tenantId, UUID userId);

    void save(User user);
}
