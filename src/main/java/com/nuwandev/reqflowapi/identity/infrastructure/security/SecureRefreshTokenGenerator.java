package com.nuwandev.reqflowapi.identity.infrastructure.security;

import com.nuwandev.reqflowapi.identity.domain.port.RefreshTokenGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class SecureRefreshTokenGenerator implements RefreshTokenGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generate() {
        byte[] buffer = new byte[32];
        secureRandom.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }
}