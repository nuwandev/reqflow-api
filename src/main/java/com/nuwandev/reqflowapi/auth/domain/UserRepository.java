package com.nuwandev.reqflowapi.auth.domain;

import java.util.UUID;

public interface UserRepository {

    User findByEmail(UUID tenantId, String email);

    User findById(UUID tenantId, UUID userId);

    void save(User user);
}
