package com.nuwandev.reqflowapi.identity.infrastructure.config;

import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * Background scheduler that evicts stale rows from the {@code auth_sessions} table,
 * preventing index bloat and keeping session lookups highly performant over time.
 *
 * <p>Two categories of rows are purged on every run:
 * <ol>
 *   <li><strong>Expired sessions</strong>: rows whose {@code expires_at} timestamp is
 *       in the past. These can never be used for a refresh.</li>
 *   <li><strong>Old revoked sessions</strong>: rows that were explicitly revoked more
 *       than {@code auth.session-cleanup.revoked-retention-days} days ago. A retention
 *       window is kept to allow forensic auditing of recent revocations.</li>
 * </ol>
 *
 * <p>The scheduler runs on a virtual-thread executor (configured via
 * {@code spring.threads.virtual.enabled=true}) so it never blocks a platform thread
 * during the DELETE scan.
 */
@Component
public class AuthSessionCleanupScheduler {

    private static final Logger log = LoggerFactory.getLogger(AuthSessionCleanupScheduler.class);

    private final AuthSessionRepository authSessionRepository;
    private final Clock clock;
    private final int revokedRetentionDays;

    public AuthSessionCleanupScheduler(
            AuthSessionRepository authSessionRepository,
            Clock clock,
            @Value("${auth.session-cleanup.revoked-retention-days:7}") int revokedRetentionDays
    ) {
        this.authSessionRepository = authSessionRepository;
        this.clock = clock;
        this.revokedRetentionDays = revokedRetentionDays;
    }

    /**
     * Runs every hour (cron: {@code 0 0 * * * *}).
     * Adjust via {@code auth.session-cleanup.cron} if higher or lower frequency is needed.
     */
    @Scheduled(cron = "${auth.session-cleanup.cron:0 0 * * * *}")
    public void purgeExpiredSessions() {
        Instant now = Instant.now(clock);
        log.info("Starting auth_sessions cleanup (revokedRetentionDays={})", revokedRetentionDays);
        try {
            int deleted = authSessionRepository.purgeExpiredAndRevoked(now, revokedRetentionDays);
            log.info("Auth session cleanup complete — {} row(s) purged", deleted);
        } catch (Exception ex) {
            // Log and swallow so a DB hiccup doesn't crash the scheduler thread.
            log.error("Auth session cleanup failed: {}", ex.getMessage(), ex);
        }
    }
}
