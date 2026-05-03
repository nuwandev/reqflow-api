package com.nuwandev.reqflowapi.auth.application.port.output;

import java.util.UUID;

public interface AuthAuditLogger {

    void loginSucceeded(UUID tenantId, UUID userId, String email, String ipAddress, String userAgent);

    void loginFailed(UUID tenantId, String email, String ipAddress, String userAgent, String reason);

    void refreshSucceeded(UUID tenantId, UUID userId, String ipAddress, String userAgent);

    void refreshFailed(String reason);

    void refreshReuseDetected(UUID tenantId, UUID userId, String ipAddress, String userAgent);

    void logoutSucceeded(UUID tenantId, UUID userId);

    void accessTokenRejected(String reason, String path, String remoteAddress);

    void rateLimitExceeded(String action, String clientKey, String remoteAddress);
}

