package com.nuwandev.reqflowapi.auth.application.port.output;

public interface PasswordHasherPort {

	String hash(String rawPassword);

	boolean matches(String rawPassword, String passwordHash);
}

