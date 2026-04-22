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
        if (passwordHash == null || passwordHash.isBlank())
            throw new IllegalArgumentException("Password hash cannot be null or blank");
        if (fullName == null || fullName.isBlank())
            throw new IllegalArgumentException("Full name cannot be null or blank");
        if (now == null)
            throw new IllegalArgumentException("Now cannot be null");

        User user = new User();
        user.id = UUID.randomUUID();
        user.tenantId = tenantId;
        user.email = normalizeAndValidateEmail(email);
        user.passwordHash = passwordHash;
        user.fullName = fullName.trim();
        user.isActive = true;
        user.createdAt = now;
        user.updatedAt = now;
        return user;
    }

    public void deactivate(Instant now) {
        this.isActive = false;
        this.updatedAt = now;
    }

    public void activate(Instant now) {
        this.isActive = true;
        this.updatedAt = now;
    }

    public void changePassword(String newPasswordHash, Instant now) {
        if (newPasswordHash == null || newPasswordHash.isBlank())
            throw new IllegalArgumentException("New password hash cannot be null or blank");
        this.passwordHash = newPasswordHash;
        this.updatedAt = now;
    }

    public void changeEmail(String newEmail, Instant now) {
        this.email = normalizeAndValidateEmail(newEmail);
        this.updatedAt = now;
    }

    public boolean isActive() {
        return this.isActive;
    }

    private static String normalizeAndValidateEmail(String email) {
        if (email == null)
            throw new IllegalArgumentException("Email cannot be null");
        String normalizedEmail = email.toLowerCase().trim();
        if (normalizedEmail.isBlank() || !normalizedEmail.contains("@"))
            throw new IllegalArgumentException("Email cannot be blank and must contain '@'");
        return normalizedEmail;
    }
}
