package com.nuwandev.reqflowapi.identity.infrastructure.security;


import com.nuwandev.reqflowapi.identity.application.port.output.AuthAuditLogger;
import com.nuwandev.reqflowapi.identity.application.port.output.AuthenticatedUser;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Component
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtPort jwtPort;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final AuthAuditLogger authAuditLogger;
    private final Clock clock;

    public BearerTokenAuthenticationFilter(
            JwtPort jwtPort,
            AuthenticationEntryPoint authenticationEntryPoint,
            AuthAuditLogger authAuditLogger,
            Clock clock
    ) {
        this.jwtPort = jwtPort;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.authAuditLogger = authAuditLogger;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.substring("Bearer ".length()).trim();
        try {
            AuthenticatedUser authenticatedUser = jwtPort.parseAndValidate(token, Instant.now(clock));
            UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                    authenticatedUser,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_" + authenticatedUser.role().name()))
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (InvalidAccessTokenException ex) {
            SecurityContextHolder.clearContext();
            authAuditLogger.accessTokenRejected(ex.getMessage(), request.getRequestURI(), request.getRemoteAddr());
            authenticationEntryPoint.commence(
                    request,
                    response,
                    new BadCredentialsException(ex.getMessage(), ex)
            );
        }
    }
}
