package com.nuwandev.reqflowapi.identity.infrastructure.persistence;

import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import com.nuwandev.reqflowapi.identity.infrastructure.persistence.entity.AuthSessionEntity;
import com.nuwandev.reqflowapi.identity.infrastructure.persistence.mapper.AuthSessionMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class JdbcAuthSessionRepository implements AuthSessionRepository {

    private static final Logger log = LoggerFactory.getLogger(JdbcAuthSessionRepository.class);

    private final JdbcTemplate jdbcTemplate;
    private final AuthSessionMapper authSessionMapper;

    private final RowMapper<AuthSessionEntity> authSessionRowMapper = (rs, rowNum) -> {
        AuthSessionEntity entity = new AuthSessionEntity();
        entity.setId(rs.getObject("id", UUID.class));
        entity.setTenantId(rs.getObject("tenant_id", UUID.class));
        entity.setUserId(rs.getObject("user_id", UUID.class));
        entity.setRefreshTokenHash(rs.getString("refresh_token_hash"));
        entity.setIpAddress(rs.getString("ip_address"));
        entity.setUserAgent(rs.getString("user_agent"));
        java.sql.Timestamp issuedAtTs = rs.getTimestamp("issued_at");
        entity.setIssuedAt(issuedAtTs != null ? issuedAtTs.toInstant() : null);
        java.sql.Timestamp expiresAtTs = rs.getTimestamp("expires_at");
        entity.setExpiresAt(expiresAtTs != null ? expiresAtTs.toInstant() : null);
        java.sql.Timestamp revokedAtTs = rs.getTimestamp("revoked_at");
        entity.setRevokedAt(revokedAtTs != null ? revokedAtTs.toInstant() : null);
        UUID replacedBySessionId = rs.getObject("replaced_by_session_id", UUID.class);
        if (rs.wasNull()) replacedBySessionId = null;
        entity.setReplacedBySessionId(replacedBySessionId);
        java.sql.Timestamp rotatedAtTs = rs.getTimestamp("rotated_at");
        entity.setRotatedAt(rotatedAtTs != null ? rotatedAtTs.toInstant() : null);
        java.sql.Timestamp createdAtTs = rs.getTimestamp("created_at");
        entity.setCreatedAt(createdAtTs != null ? createdAtTs.toInstant() : null);
        java.sql.Timestamp updatedAtTs = rs.getTimestamp("updated_at");
        entity.setUpdatedAt(updatedAtTs != null ? updatedAtTs.toInstant() : null);
        return entity;
    };

    public JdbcAuthSessionRepository(JdbcTemplate jdbcTemplate, AuthSessionMapper authSessionMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.authSessionMapper = authSessionMapper;
    }

    @Override
    public Optional<AuthSession> findById(UUID tenantId, UUID sessionId) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, ip_address, user_agent,
                       issued_at, expires_at, revoked_at, replaced_by_session_id,
                       rotated_at, created_at, updated_at
                FROM auth_sessions
                WHERE tenant_id = ? AND id = ?
                """;
        List<AuthSessionEntity> sessions = jdbcTemplate.query(sql, authSessionRowMapper, tenantId, sessionId);
        AuthSessionEntity entity = DataAccessUtils.singleResult(sessions);
        return Optional.ofNullable(entity).map(authSessionMapper::toDomain);
    }

    /**
     * Tenant-scoped lookup with a pessimistic write-lock.
     * Requiring both {@code hash} AND {@code tenantId} in the WHERE clause
     * prevents cross-tenant session access even if two tenants produced the
     * same SHA-256 hash.
     */
    @Override
    public Optional<AuthSession> findByRefreshTokenHashForUpdate(String hash, UUID tenantId) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, ip_address, user_agent,
                       issued_at, expires_at, revoked_at, replaced_by_session_id,
                       rotated_at, created_at, updated_at
                FROM auth_sessions
                WHERE refresh_token_hash = ? AND tenant_id = ?
                FOR UPDATE
                """;
        List<AuthSessionEntity> sessions = jdbcTemplate.query(sql, authSessionRowMapper, hash, tenantId);
        AuthSessionEntity entity = DataAccessUtils.singleResult(sessions);
        return Optional.ofNullable(entity).map(authSessionMapper::toDomain);
    }

    /**
     * Minimal tenant-discovery projection — no row lock, smallest possible scan.
     * Returns only tenant_id for the given token hash so the caller can construct
     * the fully scoped {@link #findByRefreshTokenHashForUpdate} call.
     */
    @Override
    public Optional<UUID> findTenantIdByRefreshTokenHash(String hash) {
        String sql = """
                SELECT tenant_id FROM auth_sessions
                WHERE refresh_token_hash = ?
                LIMIT 1
                """;
        List<UUID> results = jdbcTemplate.query(
                sql,
                (rs, rowNum) -> rs.getObject("tenant_id", UUID.class),
                hash
        );
        return results.isEmpty() ? Optional.empty() : Optional.ofNullable(results.get(0));
    }

    @Override
    public void save(AuthSession session) {
        AuthSessionEntity entity = authSessionMapper.toEntity(session);

        String updateSql = """
                UPDATE auth_sessions SET
                    revoked_at             = ?,
                    replaced_by_session_id = ?,
                    rotated_at             = ?,
                    updated_at             = ?
                WHERE id = ?
                """;

        int updated = jdbcTemplate.update(updateSql,
                entity.getRevokedAt(),
                entity.getReplacedBySessionId(),
                entity.getRotatedAt(),
                entity.getUpdatedAt(),
                entity.getId()
        );

        if (updated == 0) {
            String insertSql = """
                    INSERT INTO auth_sessions
                        (
                         id, tenant_id, user_id, refresh_token_hash,
                         ip_address, user_agent, issued_at, expires_at,
                         revoked_at, replaced_by_session_id, rotated_at,
                         created_at, updated_at
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """;

            jdbcTemplate.update(insertSql,
                    entity.getId(),
                    entity.getTenantId(),
                    entity.getUserId(),
                    entity.getRefreshTokenHash(),
                    entity.getIpAddress(),
                    entity.getUserAgent(),
                    entity.getIssuedAt(),
                    entity.getExpiresAt(),
                    entity.getRevokedAt(),
                    entity.getReplacedBySessionId(),
                    entity.getRotatedAt(),
                    entity.getCreatedAt(),
                    entity.getUpdatedAt()
            );
        }
    }

    @Override
    public void revokeAllByUserId(UUID tenantId, UUID userId, Instant now) {
        String sql = """
                UPDATE auth_sessions
                SET revoked_at = ?, updated_at = ?
                WHERE tenant_id = ?
                  AND user_id   = ?
                  AND revoked_at IS NULL
                """;
        jdbcTemplate.update(sql, now, now, tenantId, userId);
    }

    /**
     * Walks the forward replacement chain of an ancestor session and revokes every
     * live descendant in one recursive CTE update. This replaces the previous
     * in-memory while-loop, preventing partial revocations under concurrent load.
     */
    @Override
    public void revokeSessionChain(UUID tenantId, UUID ancestralSessionId, Instant now) {
        String selectSql = """
                WITH RECURSIVE chain(id, replaced_by_session_id) AS (
                    SELECT id, replaced_by_session_id
                    FROM auth_sessions
                    WHERE tenant_id = ? AND id = ?
                    UNION ALL
                    SELECT s.id, s.replaced_by_session_id
                    FROM auth_sessions s
                    INNER JOIN chain c ON s.id = c.replaced_by_session_id
                    WHERE s.tenant_id = ?
                )
                SELECT id FROM chain
                """;
        List<UUID> ids = jdbcTemplate.query(
                selectSql,
                (rs, rowNum) -> rs.getObject("id", UUID.class),
                tenantId, ancestralSessionId, tenantId
        );

        if (!ids.isEmpty()) {
            StringBuilder updateSql = new StringBuilder("UPDATE auth_sessions SET revoked_at = ?, updated_at = ? WHERE tenant_id = ? AND revoked_at IS NULL AND id IN (");
            Object[] args = new Object[3 + ids.size()];
            args[0] = now;
            args[1] = now;
            args[2] = tenantId;
            for (int i = 0; i < ids.size(); i++) {
                updateSql.append("?");
                if (i < ids.size() - 1) {
                    updateSql.append(",");
                }
                args[3 + i] = ids.get(i);
            }
            updateSql.append(")");
            int revokedRows = jdbcTemplate.update(updateSql.toString(), args);
            log.info("Revoked {} session(s) in chain from ancestral={} tenant={}", revokedRows, ancestralSessionId, tenantId);
        }
    }

    /**
     * Deletes sessions that are either fully expired or were revoked longer than
     * {@code revokedRetentionDays} days ago. Called periodically by the cleanup scheduler.
     */
    @Override
    public int purgeExpiredAndRevoked(Instant now, int revokedRetentionDays) {
        java.time.Instant revokedCutoff = now.minus(revokedRetentionDays, java.time.temporal.ChronoUnit.DAYS);
        String sql = """
                DELETE FROM auth_sessions
                WHERE expires_at < ?
                   OR (revoked_at IS NOT NULL AND revoked_at < ?)
                """;
        int deleted = jdbcTemplate.update(sql, now, revokedCutoff);
        log.info("Purged {} stale auth_session row(s) (revoked retention={}d)", deleted, revokedRetentionDays);
        return deleted;
    }
}
