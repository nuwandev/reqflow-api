package com.nuwandev.reqflowapi.auth.presentation.rest.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record LoginRequest(
        @NotNull UUID tenantId,
        @NotBlank @Email String email,
        @NotBlank String password
) {
}
