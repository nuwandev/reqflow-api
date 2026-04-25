package com.nuwandev.reqflowapi.auth.infrastructure.persistence;

import com.nuwandev.reqflowapi.auth.domain.User;
import com.nuwandev.reqflowapi.auth.domain.UserRepository;
import com.nuwandev.reqflowapi.auth.domain.UserRole;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class JdbcUserRepository implements UserRepository {

    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<User> userRowMapper = (rs, rowNum) -> {
        UUID id = (UUID) rs.getObject("id");
        UUID tenantId = (UUID) rs.getObject("tenant_id");
        String email = rs.getString("email");
        String passwordHash = rs.getString("password_hash");
        String fullName = rs.getString("full_name");
        String roleStr = rs.getString("role");
        boolean isActive = rs.getBoolean("is_active");
        Instant createdAt = rs.getTimestamp("created_at").toInstant();
        Instant updatedAt = rs.getTimestamp("updated_at").toInstant();
        UserRole role;
        try {
            role = UserRole.valueOf(roleStr);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid user role in DB: " + roleStr, e);
        }

        return User.reconstruct(
                id,
                tenantId,
                email,
                passwordHash,
                fullName,
                role,
                isActive,
                createdAt,
                updatedAt
        );
    };

    public JdbcUserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public Optional<User> findByEmail(UUID tenantId, String email) {
        return queryForOptional("""
                SELECT id, tenant_id, email, password_hash, full_name, role, is_active, created_at, updated_at
                FROM users
                WHERE tenant_id = ? AND email = ?
                """, tenantId, email.toLowerCase().trim());
    }

    @Override
    public Optional<User> findById(UUID tenantId, UUID userId) {
        return queryForOptional("""
                SELECT id, tenant_id, email, password_hash, full_name, role, is_active, created_at, updated_at
                FROM users
                WHERE tenant_id = ? AND id = ?
                """, tenantId, userId);
    }

    @Override
    public void save(User user) {
        String sql = """
                 INSERT INTO users
                     (
                      id,
                      tenant_id,
                      email,
                      password_hash,
                      full_name,
                      role,
                      is_active,
                      created_at,
                      updated_at
                      )
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (id) DO UPDATE SET
                     email = EXCLUDED.email,
                     password_hash = EXCLUDED.password_hash,
                     full_name = EXCLUDED.full_name,
                     role = EXCLUDED.role,
                     is_active = EXCLUDED.is_active,
                     updated_at = EXCLUDED.updated_at
                """;

        jdbcTemplate.update(sql,
                user.getId(),
                user.getTenantId(),
                user.getEmail(),
                user.getPasswordHash(),
                user.getFullName(),
                user.getRole().name(),
                user.isActive(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    private Optional<User> queryForOptional(String sql, Object... args) {
        List<User> results = jdbcTemplate.query(sql, userRowMapper, args);
        return Optional.ofNullable(DataAccessUtils.singleResult(results));
    }
}
