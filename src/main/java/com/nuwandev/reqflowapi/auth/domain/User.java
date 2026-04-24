package com.nuwandev.reqflowapi.auth.domain;

import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

public class User {
    @Getter
    private UUID id;
    @Getter
    private UUID tenantId;
    @Getter
    private String email;
    @Getter
    private String passwordHash;
    @Getter
    private String fullName;
    @Getter
    private UserRole role;
    @Getter
    private boolean isActive;
    @Getter
    private Instant createdAt;
    @Getter
    private Instant updatedAt;

    public static User create(
            UUID tenantId,
            String email,
            String passwordHash,
            String fullName,
            UserRole role,
            Instant now
    ) {
        if (tenantId == null)
            throw new IllegalArgumentException("Tenant ID cannot be null");
        if (passwordHash == null || passwordHash.isBlank())
            throw new IllegalArgumentException("Password hash cannot be null or blank");
        if (fullName == null || fullName.isBlank())
            throw new IllegalArgumentException("Full name cannot be null or blank");
        if (role == null)
            throw new IllegalArgumentException("Role cannot be null");
        if (now == null)
            throw new IllegalArgumentException("Now cannot be null");

        User user = new User();
        user.id = UUID.randomUUID();
        user.tenantId = tenantId;
        user.email = normalizeAndValidateEmail(email);
        user.passwordHash = passwordHash;
        user.fullName = fullName.trim();
        user.role = role;
        user.isActive = true;
        user.createdAt = now;
        user.updatedAt = now;
        return user;
    }

    public static User reconstruct(
            UUID id,
            UUID tenantId,
            String email,
            String passwordHash,
            String fullName,
            UserRole role,
            boolean isActive,
            Instant createdAt,
            Instant updatedAt
    ) {
        if (id == null)
            throw new IllegalArgumentException("User ID cannot be null");
        if (tenantId == null)
            throw new IllegalArgumentException("Tenant ID cannot be null");
        if (email == null || email.isBlank())
            throw new IllegalArgumentException("Email cannot be null or blank");
        if (passwordHash == null || passwordHash.isBlank())
            throw new IllegalArgumentException("Password hash cannot be null or blank");
        if (fullName == null || fullName.isBlank())
            throw new IllegalArgumentException("Full name cannot be null or blank");
        if (role == null)
            throw new IllegalArgumentException("Role cannot be null");
        if (createdAt == null)
            throw new IllegalArgumentException("createdAt cannot be null");
        if (updatedAt == null)
            throw new IllegalArgumentException("updatedAt cannot be null");
        User user = new User();
        user.id = id;
        user.tenantId = tenantId;
        user.email = email;
        user.passwordHash = passwordHash;
        user.fullName = fullName;
        user.role = role;
        user.isActive = isActive;
        user.createdAt = createdAt;
        user.updatedAt = updatedAt;
        return user;
    }

    public void deactivate(Instant now) {
        requireNow(now);
        if (this.isActive) {
            this.isActive = false;
        }
        this.updatedAt = now;
    }

    public void activate(Instant now) {
        requireNow(now);
        if (!this.isActive) {
            this.isActive = true;
        }
        this.updatedAt = now;
    }

    public void changePassword(String newPasswordHash, Instant now) {
        requireNow(now);
        if (newPasswordHash == null || newPasswordHash.isBlank())
            throw new IllegalArgumentException("New password hash cannot be null or blank");
        this.passwordHash = newPasswordHash;
        this.updatedAt = now;
    }

    public void changeEmail(String newEmail, Instant now) {
        requireNow(now);
        this.email = normalizeAndValidateEmail(newEmail);
        this.updatedAt = now;
    }

    public void changeRole(UserRole newRole, Instant now) {
        requireNow(now);
        if (newRole == null)
            throw new IllegalArgumentException("Role cannot be null");
        this.role = newRole;
        this.updatedAt = now;
    }

    private static String normalizeAndValidateEmail(String email) {
        if (email == null)
            throw new IllegalArgumentException("Email cannot be null");
        String normalizedEmail = email.toLowerCase().trim();
        if (normalizedEmail.isBlank() || !normalizedEmail.contains("@"))
            throw new IllegalArgumentException("Email cannot be blank and must contain '@'");
        return normalizedEmail;
    }

    private static void requireNow(Instant now) {
        if (now == null)
            throw new IllegalArgumentException("Now cannot be null");
    }
}
