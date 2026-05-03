package com.nuwandev.reqflowapi.identity.application.port.output;

public interface PasswordHasherPort {

    String hash(String rawPassword);

    boolean matches(String rawPassword, String passwordHash);
}

