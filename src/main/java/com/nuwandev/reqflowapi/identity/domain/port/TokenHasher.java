package com.nuwandev.reqflowapi.identity.domain.port;

public interface TokenHasher {
    String hash(String raw);

    boolean verify(String raw, String hash);
}
