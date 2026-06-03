package com.nuwandev.reqflowapi.identity.infrastructure.security;

import com.nuwandev.reqflowapi.identity.application.port.output.AuthenticatedUser;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
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

/**
 * JWT authentication filter that:
 * <ol>
 *   <li>Parses and cryptographically validates the Bearer token.</li>
 *   <li>Performs an inline mid-session active-status check against the database,
 *       ensuring that deactivated users cannot continue to access the API until
 *       their token expires — closing the stateless JWT revocation trade-off.</li>
 * </ol>
 */
@Component
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenAuthenticationFilter.class);

    private final JwtPort jwtPort;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final Clock clock;
    private final JdbcTemplate jdbcTemplate;

    public BearerTokenAuthenticationFilter(
            JwtPort jwtPort,
            AuthenticationEntryPoint authenticationEntryPoint,
            Clock clock,
            JdbcTemplate jdbcTemplate
    ) {
        this.jwtPort = jwtPort;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.clock = clock;
        this.jdbcTemplate = jdbcTemplate;
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

            // ── Mid-session active-status enforcement
            // JWTs are stateless by design; a deactivated user's existing token remains
            // cryptographically valid until expiry. This inline DB check closes the gap:
            // if the account has been deactivated the request is rejected immediately.
            // The query uses the composite (id, tenant_id) primary-key index — O(1) lookup.
            if (!isUserActive(authenticatedUser)) {
                log.warn("Blocked deactivated user mid-session: userId={} tenantId={}",
                        authenticatedUser.userId(), authenticatedUser.tenantId());
                sendDeactivatedResponse(response);
                return;
            }

            UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                    authenticatedUser,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_" + authenticatedUser.role().name()))
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);

        } catch (InvalidAccessTokenException ex) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(
                    request,
                    response,
                    new BadCredentialsException(ex.getMessage(), ex)
            );
        }
    }

    /**
     * Checks whether the user account is still active using a minimal single-column
     * projection against the composite primary key. Falls back to {@code false}
     * (deny) if the user row is not found.
     */
    private boolean isUserActive(AuthenticatedUser user) {
        try {
            Boolean active = jdbcTemplate.queryForObject(
                    "SELECT is_active FROM users WHERE id = ? AND tenant_id = ?",
                    Boolean.class,
                    user.userId(),
                    user.tenantId()
            );
            return Boolean.TRUE.equals(active);
        } catch (Exception ex) {
            // User not found or unexpected DB error — deny access defensively.
            log.error("Failed to verify active status for userId={}: {}", user.userId(), ex.getMessage());
            return false;
        }
    }

    private void sendDeactivatedResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"UNAUTHORIZED\",\"message\":\"User identity deactivated\"}");
    }
}
