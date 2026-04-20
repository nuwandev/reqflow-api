package com.nuwandev.reqflowapi.auth.domain;

public interface TokenHasher {
    String hash(String raw);
    boolean matches(String raw, String hash);
}
