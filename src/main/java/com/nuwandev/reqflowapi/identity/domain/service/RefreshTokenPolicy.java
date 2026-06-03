package com.nuwandev.reqflowapi.identity.domain.service;

import com.nuwandev.reqflowapi.identity.domain.exception.InactiveUserException;
import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.model.User;
import java.time.Instant;

/**
 * Domain Service for refresh token rotation policies.
 * Encapsulates multi-tab grace period rules and user status checks during refresh.
 */
public class RefreshTokenPolicy {
    private final long rotationGracePeriodSeconds;

    public RefreshTokenPolicy(long rotationGracePeriodSeconds) {
        this.rotationGracePeriodSeconds = rotationGracePeriodSeconds;
    }

    public void validateUserCanRefresh(User user) {
        if (!user.isActive()) {
            throw new InactiveUserException();
        }
    }

    /**
     * Identifies if a session reuse attempt is actually a benign concurrent-tab replay
     * within the allowed grace window.
     */
    public boolean isWithinGracePeriod(AuthSession session, Instant now) {
        return session.isReuseAttempt() && session.isWithinRotationGracePeriod(now, rotationGracePeriodSeconds);
    }
}
