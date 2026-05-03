package com.nuwandev.reqflowapi.auth.presentation.rest.dto;

import com.nuwandev.reqflowapi.auth.domain.model.UserRole;

import java.util.UUID;

public record MeResponse(UUID userId, UUID tenantId, UserRole role) {
}

