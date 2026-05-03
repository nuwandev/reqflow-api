package com.nuwandev.reqflowapi.identity.infrastructure.persistence.entity;

import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
public class UserEntity {
    private UUID id;
    private UUID tenantId;
    private String email;
    private String passwordHash;
    private String fullName;
    private String role;
    private boolean isActive;
    private Instant createdAt;
    private Instant updatedAt;
}
