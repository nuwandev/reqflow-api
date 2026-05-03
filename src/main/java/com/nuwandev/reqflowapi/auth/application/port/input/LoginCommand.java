package com.nuwandev.reqflowapi.auth.application.port.input;

import java.util.UUID;

public record LoginCommand(
        UUID tenantId,
        String email,
        String password,
        String ip,
        String userAgent
) {
}

