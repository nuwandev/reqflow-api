package com.nuwandev.reqflowapi.auth.infrastructure.security;

import com.nuwandev.reqflowapi.auth.domain.TokenHasher;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
public class Sha256TokenHasher implements TokenHasher {

    private static final HexFormat hexFormat = HexFormat.of();

    @Override
    public String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return hexFormat.formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    @Override
    public boolean matches(String raw, String hash) {
        String hashedRaw = hash(raw);
        return MessageDigest.isEqual(
            hashedRaw.getBytes(StandardCharsets.UTF_8),
            hash.getBytes(StandardCharsets.UTF_8)
        );
    }
}
