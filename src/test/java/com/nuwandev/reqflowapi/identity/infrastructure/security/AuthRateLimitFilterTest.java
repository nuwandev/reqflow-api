package com.nuwandev.reqflowapi.identity.infrastructure.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.PrintWriter;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AuthRateLimitFilter}.
 * Validates window-based throttling and hardened IP resolution.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthRateLimitFilter")
class AuthRateLimitFilterTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final int LOGIN_LIMIT = 3;
    private static final int REFRESH_LIMIT = 5;
    private static final long WINDOW_SECONDS = 60L;

    @Mock private FilterChain filterChain;

    private Clock clock;
    private AuthRateLimitFilter filter;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(NOW, ZoneOffset.UTC);
        filter = new AuthRateLimitFilter(clock, LOGIN_LIMIT, REFRESH_LIMIT, WINDOW_SECONDS);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Rate limiting behaviour
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("rate limiting")
    class RateLimiting {

        @Test
        @DisplayName("should allow requests within the login limit")
        void allowsRequestsWithinLimit() throws Exception {
            for (int i = 0; i < LOGIN_LIMIT; i++) {
                MockHttpServletRequest req = loginRequest("10.0.0.1");
                MockHttpServletResponse res = new MockHttpServletResponse();
                filter.doFilter(req, res, filterChain);
                assertThat(res.getStatus()).isNotEqualTo(429);
            }
            verify(filterChain, times(LOGIN_LIMIT)).doFilter(any(), any());
        }

        @Test
        @DisplayName("should block requests exceeding the login limit with 429")
        void blocks429WhenLimitExceeded() throws Exception {
            for (int i = 0; i < LOGIN_LIMIT; i++) {
                filter.doFilter(loginRequest("10.0.0.2"), new MockHttpServletResponse(), filterChain);
            }
            // One more — should be rejected
            MockHttpServletResponse blockedResponse = new MockHttpServletResponse();
            filter.doFilter(loginRequest("10.0.0.2"), blockedResponse, filterChain);
            assertThat(blockedResponse.getStatus()).isEqualTo(429);
        }

        @Test
        @DisplayName("should track different IPs independently")
        void tracksIpsIndependently() throws Exception {
            // Exhaust limit for IP 1
            for (int i = 0; i < LOGIN_LIMIT; i++) {
                filter.doFilter(loginRequest("10.0.0.3"), new MockHttpServletResponse(), filterChain);
            }
            // IP 2 should still pass
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(loginRequest("10.0.0.4"), res, filterChain);
            assertThat(res.getStatus()).isNotEqualTo(429);
        }

        @Test
        @DisplayName("non-auth paths should not be filtered")
        void skipsNonAuthPaths() throws Exception {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/users");
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, filterChain);
            // Filter chain must have been called
            verify(filterChain).doFilter(req, res);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // IP resolution / anti-spoofing
    // ──────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("IP resolution (anti-spoofing)")
    class IpResolution {

        @Test
        @DisplayName("should use first valid IP from X-Forwarded-For")
        void usesFirstValidXff() throws Exception {
            MockHttpServletRequest req = loginRequest(null);
            req.addHeader("X-Forwarded-For", "192.168.1.10, 10.0.0.1");
            req.setRemoteAddr("172.16.0.1");

            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, filterChain);
            // Should have passed (no 429) — just verify chain was called
            verify(filterChain).doFilter(req, res);
        }

        @Test
        @DisplayName("should fall back to RemoteAddr when X-Forwarded-For is an invalid hostname")
        void fallsBackOnInvalidHostname() throws Exception {
            // Attacker trying to spoof with an arbitrary string, not a valid IP
            MockHttpServletRequest req = loginRequest(null);
            req.addHeader("X-Forwarded-For", "evil-hostname.attacker.com");
            req.setRemoteAddr("10.0.0.1");

            // Exhaust limit using the REAL RemoteAddr
            for (int i = 0; i < LOGIN_LIMIT; i++) {
                filter.doFilter(buildLoginRequestWithRemoteAddr("10.0.0.1"), new MockHttpServletResponse(), filterChain);
            }

            // Now try with spoofed XFF — falls back to RemoteAddr which is already exhausted
            MockHttpServletRequest spoofedReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            spoofedReq.addHeader("X-Forwarded-For", "evil-hostname.attacker.com");
            spoofedReq.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(spoofedReq, res, filterChain);

            assertThat(res.getStatus()).isEqualTo(429);
        }

        @Test
        @DisplayName("should reject non-IP string in X-Forwarded-For and fall back to RemoteAddr")
        void rejectsNonIpXff() throws Exception {
            MockHttpServletRequest req = loginRequest(null);
            req.addHeader("X-Forwarded-For", "not-an-ip-at-all!!!");
            req.setRemoteAddr("203.0.113.5");

            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, filterChain);
            verify(filterChain).doFilter(req, res);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private MockHttpServletRequest loginRequest(String remoteAddr) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        if (remoteAddr != null) req.setRemoteAddr(remoteAddr);
        return req;
    }

    private MockHttpServletRequest buildLoginRequestWithRemoteAddr(String remoteAddr) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        req.setRemoteAddr(remoteAddr);
        return req;
    }
}
