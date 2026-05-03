package com.nuwandev.reqflowapi.auth.application.port.input;

import java.util.UUID;

public record LogoutCommand(
        UUID tenantId,
        UUID userId
) {
}

