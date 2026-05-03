package com.nuwandev.reqflowapi.identity.application.port.output;

import com.nuwandev.reqflowapi.identity.domain.model.UserRole;

import java.util.UUID;

public record AuthenticatedUser(
        UUID userId,
        UUID tenantId,
        UserRole role
) {
}

