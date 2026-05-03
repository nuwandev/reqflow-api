package com.nuwandev.reqflowapi.auth.application.port.output;

public interface TokenHasher {
    String hash(String raw);

    boolean verify(String raw, String hash);
}
