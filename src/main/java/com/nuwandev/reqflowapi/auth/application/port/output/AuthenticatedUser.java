package com.nuwandev.reqflowapi.auth.application.port.output;

import com.nuwandev.reqflowapi.auth.domain.model.UserRole;

import java.util.UUID;

public record AuthenticatedUser(
        UUID userId,
        UUID tenantId,
        UserRole role
) {
}

