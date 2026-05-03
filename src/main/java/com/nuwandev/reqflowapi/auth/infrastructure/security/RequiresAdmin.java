package com.nuwandev.reqflowapi.auth.infrastructure.security;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@authz.hasRole(T(com.nuwandev.reqflowapi.auth.domain.model.UserRole).ADMIN)")
public @interface RequiresAdmin {
}
