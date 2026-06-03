package com.nuwandev.reqflowapi.identity.infrastructure.security;

import com.nuwandev.reqflowapi.identity.domain.port.TokenHasher;
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
        byte[] hashBytes = getDigest(raw);
        return hexFormat.formatHex(hashBytes);
    }

    @Override
    public boolean verify(String raw, String hash) {
        byte[] expected = getDigest(raw);
        byte[] actual;
        try {
            actual = hexFormat.parseHex(hash);
        } catch (IllegalArgumentException e) {
            return false;
        }
        return MessageDigest.isEqual(expected, actual);
    }

    private byte[] getDigest(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(raw.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
