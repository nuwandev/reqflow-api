package com.nuwandev.reqflowapi.identity.presentation.rest.dto;

import com.nuwandev.reqflowapi.identity.domain.model.UserRole;

import java.util.UUID;

public record MeResponse(UUID userId, UUID tenantId, UserRole role) {
}

