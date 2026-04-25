package com.nuwandev.reqflowapi.auth.domain;

public interface TokenHasher {
    String hash(String raw);

    boolean verify(String raw, String hash);
}
