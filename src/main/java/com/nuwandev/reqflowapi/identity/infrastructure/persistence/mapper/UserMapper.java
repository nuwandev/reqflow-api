package com.nuwandev.reqflowapi.identity.infrastructure.persistence.mapper;

import com.nuwandev.reqflowapi.identity.domain.model.User;
import com.nuwandev.reqflowapi.identity.domain.model.UserRole;
import com.nuwandev.reqflowapi.identity.infrastructure.persistence.entity.UserEntity;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public UserEntity toEntity(User user) {
        if (user == null) {
            return null;
        }
        UserEntity entity = new UserEntity();
        entity.setId(user.getId());
        entity.setTenantId(user.getTenantId());
        entity.setEmail(user.getEmail());
        entity.setPasswordHash(user.getPasswordHash());
        entity.setFullName(user.getFullName());
        entity.setRole(user.getRole() != null ? user.getRole().name() : null);
        entity.setActive(user.isActive());
        entity.setCreatedAt(user.getCreatedAt());
        entity.setUpdatedAt(user.getUpdatedAt());
        return entity;
    }

    public User toDomain(UserEntity entity) {
        if (entity == null) {
            return null;
        }
        return User.reconstruct(
                entity.getId(),
                entity.getTenantId(),
                entity.getEmail(),
                entity.getPasswordHash(),
                entity.getFullName(),
                entity.getRole() != null ? UserRole.valueOf(entity.getRole()) : null,
                entity.isActive(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }
}
