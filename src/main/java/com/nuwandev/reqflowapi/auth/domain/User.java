package com.nuwandev.reqflowapi.auth.domain;

import java.time.Instant;
import java.util.UUID;

public class User {
    private UUID id;
    private UUID tenantId;
    private String email;
    private String passwordHash;
    private String fullName;
    private String role;
    private boolean isActive;
    private Instant createdAt;
    private Instant updatedAt;

    public static User create(
            UUID tenantId,
            String email,
            String passwordHash,
            String fullName,
            Instant now
    ) {
        if (tenantId == null)
            throw new IllegalArgumentException("Tenant ID cannot be null");
        if (email == null || email.isBlank() || !email.contains("@"))
            throw new IllegalArgumentException("Email cannot be null, blank, and must contain '@'");
        if (passwordHash == null || passwordHash.isBlank())
            throw new IllegalArgumentException("Password hash cannot be null or blank");
        if (fullName == null || fullName.isBlank())
            throw new IllegalArgumentException("Full name cannot be null or blank");
        if  (now == null)
            throw new IllegalArgumentException("Now cannot be null");

        User user = new User();
        user.id = UUID.randomUUID();
        user.tenantId = tenantId;
        user.email = email.toLowerCase().trim();
        user.passwordHash = passwordHash;
        user.fullName = fullName.trim();
        user.isActive = true;
        user.createdAt = now;
        user.updatedAt = now;
        return user;
    }

    public void deactivate() {
        this.isActive = false;
    }

    public void activate() {
        this.isActive = true;
    }

    public void changePassword(String newPasswordHash) {
        if (newPasswordHash == null || newPasswordHash.isBlank())
            throw new IllegalArgumentException("New password hash cannot be null or blank");
        this.passwordHash = newPasswordHash;
    }

    public void changeEmail(String newEmail) {
        if (newEmail == null || newEmail.isBlank())
            throw new IllegalArgumentException("Email cannot be null or blank");
        this.email = newEmail.toLowerCase().trim();
    }

    public boolean isActive() {
        return this.isActive;
    }
}
