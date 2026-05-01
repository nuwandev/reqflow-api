package com.nuwandev.reqflowapi.auth.infrastructure.persistence;

import com.nuwandev.reqflowapi.auth.domain.AuthSession;
import com.nuwandev.reqflowapi.auth.domain.AuthSessionRepository;
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

    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<AuthSession> authSessionRowMapper = (rs, rowNum) -> {
        UUID id = rs.getObject("id", UUID.class);
        UUID tenantId = rs.getObject("tenant_id", UUID.class);
        UUID userId = rs.getObject("user_id", UUID.class);
        String refreshTokenHash = rs.getString("refresh_token_hash");
        String ipAddress = rs.getString("ip_address");
        String userAgent = rs.getString("user_agent");
        java.sql.Timestamp issuedAtTs = rs.getTimestamp("issued_at");
        Instant issuedAt = issuedAtTs != null ? issuedAtTs.toInstant() : null;
        java.sql.Timestamp expiresAtTs = rs.getTimestamp("expires_at");
        Instant expiresAt = expiresAtTs != null ? expiresAtTs.toInstant() : null;
        java.sql.Timestamp revokedAtTs = rs.getTimestamp("revoked_at");
        Instant revokedAt = revokedAtTs != null ? revokedAtTs.toInstant() : null;
        UUID replacedBySessionId = rs.getObject("replaced_by_session_id", UUID.class);
        if (rs.wasNull()) replacedBySessionId = null;
        java.sql.Timestamp createdAtTs = rs.getTimestamp("created_at");
        Instant createdAt = createdAtTs != null ? createdAtTs.toInstant() : null;
        java.sql.Timestamp updatedAtTs = rs.getTimestamp("updated_at");
        Instant updatedAt = updatedAtTs != null ? updatedAtTs.toInstant() : null;
        return AuthSession.reconstruct(
                id,
                tenantId,
                userId,
                refreshTokenHash,
                ipAddress,
                userAgent,
                issuedAt,
                expiresAt,
                revokedAt,
                replacedBySessionId,
                createdAt,
                updatedAt
        );
    };

    public JdbcAuthSessionRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public Optional<AuthSession> findById(UUID tenantId, UUID sessionId) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, ip_address, user_agent, issued_at, expires_at, revoked_at, replaced_by_session_id, created_at, updated_at
                FROM auth_sessions
                WHERE tenant_id = ? AND id = ?
                """;

        List<AuthSession> sessions = jdbcTemplate.query(sql, authSessionRowMapper, tenantId, sessionId);
        return Optional.ofNullable(DataAccessUtils.singleResult(sessions));
    }

    @Override
    public Optional<AuthSession> findByRefreshTokenHashForUpdate(String hash) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, ip_address, user_agent, issued_at, expires_at, revoked_at, replaced_by_session_id, created_at, updated_at
                FROM auth_sessions
                WHERE refresh_token_hash = ?
                FOR UPDATE
                """;

        List<AuthSession> sessions = jdbcTemplate.query(sql, authSessionRowMapper, hash);
        return Optional.ofNullable(DataAccessUtils.singleResult(sessions));
    }

    @Override
    public void save(AuthSession session) {
        String sql = """
                INSERT INTO auth_sessions
                    (
                     id,
                     tenant_id,
                     user_id,
                     refresh_token_hash,
                     ip_address,
                     user_agent,
                     issued_at,
                     expires_at,
                     revoked_at,
                     replaced_by_session_id,
                     created_at,
                     updated_at
                     )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    revoked_at = EXCLUDED.revoked_at,
                    replaced_by_session_id = EXCLUDED.replaced_by_session_id,
                    updated_at = EXCLUDED.updated_at
                """;

        int rows = jdbcTemplate.update(sql,
                session.getId(),
                session.getTenantId(),
                session.getUserId(),
                session.getRefreshTokenHash(),
                session.getIpAddress(),
                session.getUserAgent(),
                session.getIssuedAt(),
                session.getExpiresAt(),
                session.getRevokedAt(),
                session.getReplacedBySessionId(),
                session.getCreatedAt(),
                session.getUpdatedAt()
        );
        if (rows == 0) {
            throw new IllegalStateException("Concurrent modification detected on auth session");
        }
    }

    @Override
    public void revokeAllByUserId(UUID tenantId, UUID userId, Instant now) {
        String sql = """
                UPDATE auth_sessions
                SET revoked_at = ?, updated_at = ?
                WHERE tenant_id = ?
                  AND user_id = ?
                  AND revoked_at IS NULL
                """;

        jdbcTemplate.update(sql, now, now, tenantId, userId);
    }
}
