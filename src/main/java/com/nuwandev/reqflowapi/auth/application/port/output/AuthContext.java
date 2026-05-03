package com.nuwandev.reqflowapi.auth.application.port.output;

import com.nuwandev.reqflowapi.auth.application.port.output.AuthenticatedUser;
import com.nuwandev.reqflowapi.auth.domain.model.UserRole;

import java.util.Optional;
import java.util.UUID;

public interface AuthContext {

    AuthenticatedUser currentUser();

    Optional<AuthenticatedUser> currentUserOptional();

    default UUID currentUserId() {
        return currentUser().userId();
    }

    default UUID currentTenantId() {
        return currentUser().tenantId();
    }

    default UserRole currentRole() {
        return currentUser().role();
    }
}

