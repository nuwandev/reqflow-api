package com.nuwandev.reqflowapi.identity.infrastructure.security;

import com.nuwandev.reqflowapi.identity.application.port.output.AuthContext;
import com.nuwandev.reqflowapi.identity.application.port.output.AuthenticatedUser;
import com.nuwandev.reqflowapi.identity.domain.model.UserRole;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.UUID;

/**
 * Spring AOP aspect that enforces the custom security annotations at method
 * invocation time, replacing the previously dead-code-only guard with an
 * active runtime interceptor.
 *
 * <p>Annotations handled:
 * <ul>
 *   <li>{@link RequiresAdmin} — caller must hold the {@code ADMIN} role.</li>
 *   <li>{@link TenantAccess} — caller's tenant must match the first {@link UUID}
 *       argument on the annotated method.</li>
 *   <li>{@link CurrentUserOrAdmin} — caller must either be the specific user
 *       (first {@link UUID} argument) or hold the {@code ADMIN} role.</li>
 * </ul>
 *
 * <p>All violations are surfaced as {@link AccessDeniedException}, which Spring
 * Security maps to a 403 response via the configured access-denied handler.
 */
@Aspect
@Component
public class AuthorizationAspect {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationAspect.class);

    private final AuthContext authContext;

    public AuthorizationAspect(AuthContext authContext) {
        this.authContext = authContext;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // @RequiresAdmin
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Intercepts any method annotated with {@link RequiresAdmin}.
     * Rejects the call unless the authenticated principal holds the {@code ADMIN} role.
     */
    @Before("@annotation(requiresAdmin)")
    public void verifyAdminRole(JoinPoint joinPoint, RequiresAdmin requiresAdmin) {
        AuthenticatedUser currentUser = authContext.currentUser();
        if (currentUser.role() != UserRole.ADMIN) {
            log.warn("Access denied: method={} userId={} role={} — ADMIN role required",
                    joinPoint.getSignature().toShortString(), currentUser.userId(), currentUser.role());
            throw new AccessDeniedException(
                    "Insufficient authorization: Administrator clearance required.");
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // @TenantAccess
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Intercepts any method annotated with {@link TenantAccess}.
     * Rejects the call if the authenticated principal's tenant does not match the
     * first {@link UUID} parameter of the annotated method.
     *
     * <p>Method-argument resolution strategy: scans the argument list for the first
     * non-null {@link UUID} value. Methods that need a specific tenant parameter
     * should place it first in the signature.
     */
    @Before("@annotation(tenantAccess)")
    public void verifyTenantAccess(JoinPoint joinPoint, TenantAccess tenantAccess) {
        AuthenticatedUser currentUser = authContext.currentUser();
        UUID routeTenantId = resolveFirstUuidArg(joinPoint, "TenantAccess");

        if (!currentUser.tenantId().equals(routeTenantId)) {
            log.warn("Cross-tenant access violation: method={} userId={} callerTenant={} routeTenant={}",
                    joinPoint.getSignature().toShortString(),
                    currentUser.userId(), currentUser.tenantId(), routeTenantId);
            throw new AccessDeniedException(
                    "Cross-tenant access violation: operation not permitted.");
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // @CurrentUserOrAdmin
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Intercepts any method annotated with {@link CurrentUserOrAdmin}.
     * Allows the call if the authenticated principal is the target user (first UUID
     * argument) OR holds the {@code ADMIN} role.
     */
    @Before("@annotation(currentUserOrAdmin)")
    public void verifyCurrentUserOrAdmin(JoinPoint joinPoint, CurrentUserOrAdmin currentUserOrAdmin) {
        AuthenticatedUser currentUser = authContext.currentUser();

        // ADMIN bypass — no further check needed.
        if (currentUser.role() == UserRole.ADMIN) {
            return;
        }

        UUID targetUserId = resolveFirstUuidArg(joinPoint, "CurrentUserOrAdmin");
        if (!currentUser.userId().equals(targetUserId)) {
            log.warn("Access denied: method={} userId={} targetUserId={} — must be current user or admin",
                    joinPoint.getSignature().toShortString(), currentUser.userId(), targetUserId);
            throw new AccessDeniedException(
                    "Access denied: you may only perform this operation on your own account.");
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Scans the method arguments for the first non-null {@link UUID} value.
     * Throws {@link IllegalArgumentException} if no UUID argument is found — this
     * indicates a misconfigured annotation placement.
     */
    private UUID resolveFirstUuidArg(JoinPoint joinPoint, String annotationName) {
        return Arrays.stream(joinPoint.getArgs())
                .filter(arg -> arg instanceof UUID)
                .map(arg -> (UUID) arg)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "@" + annotationName + " requires at least one UUID argument in the method signature " +
                                "to resolve the security context parameter. Check: " +
                                joinPoint.getSignature().toShortString()));
    }
}
