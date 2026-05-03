package com.nuwandev.reqflowapi.auth.infrastructure.security;

import com.nuwandev.reqflowapi.auth.application.port.output.AuthContext;
import com.nuwandev.reqflowapi.auth.application.port.output.AuthenticatedUser;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class SecurityContextAuthContext implements AuthContext {

    @Override
    public AuthenticatedUser currentUser() {
        return currentUserOptional()
                .orElseThrow(() -> new InsufficientAuthenticationException("Authenticated user is required"));
    }

    @Override
    public Optional<AuthenticatedUser> currentUserOptional() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof AuthenticatedUser authenticatedUser)) {
            return Optional.empty();
        }
        return Optional.of(authenticatedUser);
    }
}
