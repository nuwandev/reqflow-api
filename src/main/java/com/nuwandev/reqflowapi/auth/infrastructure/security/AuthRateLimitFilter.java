package com.nuwandev.reqflowapi.auth.infrastructure.security;

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

    private final Clock clock;
    private final int loginLimit;
    private final int refreshLimit;
    private final long windowSeconds;
    private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();

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

    private String resolveClientKey(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        String remoteAddress = request.getRemoteAddr();
        return remoteAddress != null ? remoteAddress : "unknown";
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
