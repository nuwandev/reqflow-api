package com.nuwandev.reqflowapi.identity.infrastructure.persistence.mapper;

import com.nuwandev.reqflowapi.identity.domain.model.AuthSession;
import com.nuwandev.reqflowapi.identity.infrastructure.persistence.entity.AuthSessionEntity;
import org.springframework.stereotype.Component;

@Component
public class AuthSessionMapper {

    public AuthSessionEntity toEntity(AuthSession session) {
        if (session == null) {
            return null;
        }
        AuthSessionEntity entity = new AuthSessionEntity();
        entity.setId(session.getId());
        entity.setTenantId(session.getTenantId());
        entity.setUserId(session.getUserId());
        entity.setRefreshTokenHash(session.getRefreshTokenHash());
        entity.setIpAddress(session.getIpAddress());
        entity.setUserAgent(session.getUserAgent());
        entity.setIssuedAt(session.getIssuedAt());
        entity.setExpiresAt(session.getExpiresAt());
        entity.setRevokedAt(session.getRevokedAt());
        entity.setReplacedBySessionId(session.getReplacedBySessionId());
        entity.setRotatedAt(session.getRotatedAt());
        entity.setCreatedAt(session.getCreatedAt());
        entity.setUpdatedAt(session.getUpdatedAt());
        return entity;
    }

    public AuthSession toDomain(AuthSessionEntity entity) {
        if (entity == null) {
            return null;
        }
        return AuthSession.reconstruct(
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
