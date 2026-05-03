package com.nuwandev.reqflowapi.identity.application.port.input;

import java.util.UUID;

public record LogoutCommand(
        UUID tenantId,
        UUID userId
) {
}

