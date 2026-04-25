package com.nuwandev.reqflowapi.auth.infrastructure.persistence;

import com.nuwandev.reqflowapi.auth.domain.AuthSession;
import com.nuwandev.reqflowapi.auth.domain.AuthSessionRepository;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class JdbcAuthSessionRepository implements AuthSessionRepository {

    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<AuthSession> authSessionRowMapper = (rs, rowNum) -> {
        UUID id = rs.getObject("id", UUID.class);
        UUID tenantId = rs.getObject("tenant_id", UUID.class);
        UUID userId = rs.getObject("user_id", UUID.class);
        String refreshTokenHash = rs.getString("refresh_token_hash");
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
    public Optional<AuthSession> findByRefreshTokenHash(UUID tenantId, String hash) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, issued_at, expires_at, revoked_at, replaced_by_session_id, created_at, updated_at
                FROM auth_sessions
                WHERE tenant_id = ? AND refresh_token_hash = ?
                """;

        List<AuthSession> sessions = jdbcTemplate.query(sql, authSessionRowMapper, tenantId, hash);
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
                     issued_at,
                     expires_at,
                     revoked_at,
                     replaced_by_session_id,
                     created_at,
                     updated_at
                     )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    @Override
    public List<AuthSession> findAllActiveByUserId(UUID tenantId, UUID userId, Instant now) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, issued_at, expires_at, revoked_at, replaced_by_session_id, created_at, updated_at
                FROM auth_sessions
                WHERE tenant_id = ?
                  AND user_id = ?
                  AND revoked_at IS NULL
                  AND expires_at > ?
                """;

        return jdbcTemplate.query(sql, authSessionRowMapper, tenantId, userId, now);
    }
}