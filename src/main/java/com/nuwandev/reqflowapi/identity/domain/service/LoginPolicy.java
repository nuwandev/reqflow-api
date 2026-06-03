package com.nuwandev.reqflowapi.identity.domain.service;

import com.nuwandev.reqflowapi.identity.domain.exception.InactiveUserException;
import com.nuwandev.reqflowapi.identity.domain.exception.InvalidCredentialsException;
import com.nuwandev.reqflowapi.identity.domain.model.User;
import com.nuwandev.reqflowapi.identity.domain.port.PasswordHasherPort;

/**
 * Domain Service that encapsulates the policy for user authentication.
 * Cross-aggregate rule: requires both a User entity and a PasswordHasherPort.
 */
public class LoginPolicy {
    private final PasswordHasherPort passwordHasher;

    public LoginPolicy(PasswordHasherPort passwordHasher) {
        this.passwordHasher = passwordHasher;
    }

    public void validateUserCanLogin(User user, String rawPassword) {
        if (!user.isActive()) {
            throw new InactiveUserException();
        }
        if (!passwordHasher.matches(rawPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
    }
}
