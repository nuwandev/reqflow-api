package com.nuwandev.reqflowapi.auth.application.port.output;

import com.nuwandev.reqflowapi.auth.domain.model.User;

import java.time.Instant;
import java.util.UUID;

public interface JwtPort {

	String generateAccessToken(UUID tenantId, User user, Instant now);

	AuthenticatedUser parseAndValidate(String token, Instant now);
}

