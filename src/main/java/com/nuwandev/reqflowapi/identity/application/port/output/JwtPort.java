package com.nuwandev.reqflowapi.identity.application.port.output;

import com.nuwandev.reqflowapi.identity.domain.model.User;

import java.time.Instant;
import java.util.UUID;

public interface JwtPort {

    String generateAccessToken(UUID tenantId, User user, Instant now);

    AuthenticatedUser parseAndValidate(String token, Instant now);
}

