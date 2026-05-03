package com.nuwandev.reqflowapi.auth.infrastructure.persistence;

import com.nuwandev.reqflowapi.auth.infrastructure.persistence.mapper.UserMapper;
import com.nuwandev.reqflowapi.auth.domain.model.User;
import com.nuwandev.reqflowapi.auth.domain.repository.UserRepository;
import com.nuwandev.reqflowapi.auth.infrastructure.persistence.entity.UserEntity;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class JdbcUserRepository implements UserRepository {

    private final JdbcTemplate jdbcTemplate;
    private final UserMapper userMapper;

    private final RowMapper<UserEntity> userRowMapper = (rs, rowNum) -> {
        UserEntity entity = new UserEntity();
        entity.setId((UUID) rs.getObject("id"));
        entity.setTenantId((UUID) rs.getObject("tenant_id"));
        entity.setEmail(rs.getString("email"));
        entity.setPasswordHash(rs.getString("password_hash"));
        entity.setFullName(rs.getString("full_name"));
        entity.setRole(rs.getString("role"));
        entity.setActive(rs.getBoolean("is_active"));
        entity.setCreatedAt(rs.getTimestamp("created_at").toInstant());
        entity.setUpdatedAt(rs.getTimestamp("updated_at").toInstant());
        return entity;
    };

    public JdbcUserRepository(JdbcTemplate jdbcTemplate, UserMapper userMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.userMapper = userMapper;
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

        UserEntity entity = userMapper.toEntity(user);
        jdbcTemplate.update(sql,
                entity.getId(),
                entity.getTenantId(),
                entity.getEmail(),
                entity.getPasswordHash(),
                entity.getFullName(),
                entity.getRole(),
                entity.isActive(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    private Optional<User> queryForOptional(String sql, Object... args) {
        List<UserEntity> results = jdbcTemplate.query(sql, userRowMapper, args);
        UserEntity entity = DataAccessUtils.singleResult(results);
        return Optional.ofNullable(entity).map(userMapper::toDomain);
    }
}
