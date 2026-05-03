package com.nuwandev.reqflowapi.auth.infrastructure.security;

import com.nuwandev.reqflowapi.auth.application.port.output.AuthContext;
import com.nuwandev.reqflowapi.auth.application.port.output.AuthenticatedUser;
import com.nuwandev.reqflowapi.auth.domain.model.UserRole;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.UUID;

@Component("authz")
public class AuthorizationGuard {

    private final AuthContext authContext;

    public AuthorizationGuard(AuthContext authContext) {
        this.authContext = authContext;
    }

    public boolean hasRole(UserRole role) {
        return currentUser().role() == role;
    }

    public boolean hasAnyRole(UserRole... roles) {
        UserRole currentRole = currentUser().role();
        return Arrays.stream(roles).anyMatch(role -> role == currentRole);
    }

    public boolean belongsToTenant(UUID tenantId) {
        return currentUser().tenantId().equals(tenantId);
    }

    public boolean isCurrentUser(UUID userId) {
        return currentUser().userId().equals(userId);
    }

    private AuthenticatedUser currentUser() {
        return authContext.currentUser();
    }
}
