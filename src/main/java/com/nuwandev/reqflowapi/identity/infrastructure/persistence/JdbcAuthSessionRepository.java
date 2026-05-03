package com.nuwandev.reqflowapi.identity.infrastructure.persistence;

import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import com.nuwandev.reqflowapi.identity.infrastructure.persistence.entity.AuthSessionEntity;
import com.nuwandev.reqflowapi.identity.infrastructure.persistence.mapper.AuthSessionMapper;
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
                SELECT id, tenant_id, user_id, refresh_token_hash, ip_address, user_agent, issued_at, expires_at, revoked_at, replaced_by_session_id, created_at, updated_at
                FROM auth_sessions
                WHERE tenant_id = ? AND id = ?
                """;

        List<AuthSessionEntity> sessions = jdbcTemplate.query(sql, authSessionRowMapper, tenantId, sessionId);
        AuthSessionEntity entity = DataAccessUtils.singleResult(sessions);
        return Optional.ofNullable(entity).map(authSessionMapper::toDomain);
    }

    @Override
    public Optional<AuthSession> findByRefreshTokenHashForUpdate(String hash) {
        String sql = """
                SELECT id, tenant_id, user_id, refresh_token_hash, ip_address, user_agent, issued_at, expires_at, revoked_at, replaced_by_session_id, created_at, updated_at
                FROM auth_sessions
                WHERE refresh_token_hash = ?
                FOR UPDATE
                """;

        List<AuthSessionEntity> sessions = jdbcTemplate.query(sql, authSessionRowMapper, hash);
        AuthSessionEntity entity = DataAccessUtils.singleResult(sessions);
        return Optional.ofNullable(entity).map(authSessionMapper::toDomain);
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

        AuthSessionEntity entity = authSessionMapper.toEntity(session);
        int rows = jdbcTemplate.update(sql,
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
                entity.getCreatedAt(),
                entity.getUpdatedAt()
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
