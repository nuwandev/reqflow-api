package com.nuwandev.reqflowapi.identity.application.port.output;

public interface TokenHasher {
    String hash(String raw);

    boolean verify(String raw, String hash);
}
