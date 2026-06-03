package com.nuwandev.reqflowapi.identity.infrastructure.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class AuthRateLimitFilter extends OncePerRequestFilter {

    private static final int CLEANUP_EVERY = 200;

    private final Clock clock;
    private final int loginLimit;
    private final int refreshLimit;
    private final long windowSeconds;
    private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();
    private final AtomicInteger cleanupTicker = new AtomicInteger(0);

    public AuthRateLimitFilter(
            Clock clock,
            @Value("${auth.rate-limit.login-per-window:5}") int loginLimit,
            @Value("${auth.rate-limit.refresh-per-window:10}") int refreshLimit,
            @Value("${auth.rate-limit.window-seconds:60}") long windowSeconds
    ) {
        this.clock = clock;
        this.loginLimit = loginLimit;
        this.refreshLimit = refreshLimit;
        this.windowSeconds = windowSeconds;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = resolvePath(request);
        return !"/api/v1/auth/login".equals(path) && !"/api/v1/auth/refresh".equals(path);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String path = resolvePath(request);
        String clientKey = resolveClientKey(request);
        int limit = "/api/v1/auth/login".equals(path) ? loginLimit : refreshLimit;

        if (!tryConsume(path, clientKey, limit)) {
            response.setStatus(429);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"rate_limited\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean tryConsume(String action, String clientKey, int limit) {
        Instant now = Instant.now(clock);
        maybeCleanup(now);
        String bucketKey = action + ":" + clientKey;
        WindowCounter counter = counters.compute(bucketKey, (key, existing) -> {
            if (existing == null || existing.windowEndsAt.isBefore(now)) {
                return new WindowCounter(now.plusSeconds(windowSeconds));
            }
            return existing;
        });

        int current = counter.count.incrementAndGet();
        return current <= limit;
    }

    private void maybeCleanup(Instant now) {
        if (cleanupTicker.incrementAndGet() % CLEANUP_EVERY != 0) {
            return;
        }
        counters.entrySet().removeIf(entry -> entry.getValue().windowEndsAt.isBefore(now));
    }

    /**
     * Resolves the canonical client IP used as the rate-limit bucket key.
     *
     * <p>The {@code X-Forwarded-For} header is processed by extracting the
     * <em>first</em> IP in the chain (the original client address) and validating
     * it against a strict IPv4/IPv6 format check before trusting it. This prevents
     * attackers from bypassing the rate limiter by cycling arbitrary strings in the
     * header; an invalid or missing format causes an immediate fall-back to the
     * network-layer {@code RemoteAddr}, which cannot be spoofed by the client.
     *
     * <p><strong>Note:</strong> for production deployments behind a trusted reverse
     * proxy, consider also validating that the request originates from a known proxy
     * CIDR range before accepting {@code X-Forwarded-For} at all.
     */
    private String resolveClientKey(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            String candidateIp = forwardedFor.split(",")[0].trim();
            if (isValidIpFormat(candidateIp)) {
                return candidateIp;
            }
            // Invalid format — do not trust the header; fall through to RemoteAddr.
        }
        String remoteAddress = request.getRemoteAddr();
        return remoteAddress != null ? remoteAddress : "unknown";
    }

    /**
     * Validates that the given string is a syntactically valid IPv4 or IPv6 address.
     * Uses {@link java.net.InetAddress} parsing via a try/catch to leverage the JDK's
     * own battle-tested address parser rather than a fragile hand-rolled regex.
     */
    private boolean isValidIpFormat(String ip) {
        if (ip == null || ip.isBlank()) return false;
        try {
            java.net.InetAddress.getByName(ip);
            // Reject hostnames — InetAddress.getByName resolves them; we only want literals.
            // A pure IP literal never contains letters (other than hex in IPv6) or dots
            // followed by non-digits. The simplest discriminator: if the input contains
            // only valid IP characters (digits, dots, colons, hex A-F) it is a literal.
            return ip.matches("^[0-9a-fA-F:.]+$");
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }

    private String resolvePath(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path != null ? path : "";
    }

    private static final class WindowCounter {
        private final Instant windowEndsAt;
        private final AtomicInteger count = new AtomicInteger(0);

        private WindowCounter(Instant windowEndsAt) {
            this.windowEndsAt = windowEndsAt;
        }
    }
}
