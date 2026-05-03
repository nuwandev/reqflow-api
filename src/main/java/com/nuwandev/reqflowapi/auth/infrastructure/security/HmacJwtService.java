package com.nuwandev.reqflowapi.auth.infrastructure.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nuwandev.reqflowapi.auth.application.port.output.AuthenticatedUser;
import com.nuwandev.reqflowapi.auth.application.port.output.JwtPort;
import com.nuwandev.reqflowapi.auth.domain.model.User;
import com.nuwandev.reqflowapi.auth.domain.model.UserRole;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class HmacJwtService implements JwtPort {
    private final String secret;
    private final String issuer;
    private final long accessTokenTtlSeconds;
    private final long clockSkewSeconds;
    private byte[] signingKey;
    private MACSigner signer;
    private MACVerifier verifier;

    public HmacJwtService(
            @Value("${auth.jwt.secret}") String secret,
            @Value("${auth.jwt.issuer:reqflow-api}") String issuer,
            @Value("${auth.access-token-ttl-seconds:900}") long accessTokenTtlSeconds,
            @Value("${auth.jwt-clock-skew-seconds:30}") long clockSkewSeconds
    ) {
        this.secret = secret;
        this.issuer = issuer;
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.clockSkewSeconds = clockSkewSeconds;
    }

    @PostConstruct
    void validateConfiguration() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("auth.jwt.secret must be configured");
        }
        if ("change-me-to-a-long-random-secret".equals(secret)) {
            throw new IllegalStateException("auth.jwt.secret must not use the default value");
        }
        this.signingKey = secret.getBytes(StandardCharsets.UTF_8);
        if (signingKey.length < 32) {
            throw new IllegalStateException("auth.jwt.secret must be at least 32 bytes");
        }
        if (clockSkewSeconds < 0) {
            throw new IllegalStateException("auth.jwt-clock-skew-seconds must be >= 0");
        }
        try {
            this.signer = new MACSigner(signingKey);
            this.verifier = new MACVerifier(signingKey);
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to initialize JWT signer", e);
        }
    }

    @Override
    public String generateAccessToken(UUID tenantId, User user, Instant now) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        if (now == null) {
            throw new IllegalArgumentException("Now cannot be null");
        }

        Instant expiresAt = now.plusSeconds(accessTokenTtlSeconds);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(user.getId().toString())
                .audience("reqflow-api")
                .claim("tenantId", tenantId.toString())
                .claim("role", user.getRole().name())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claimsSet
        );
        try {
            signedJwt.sign(signer);
            return signedJwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    @Override
    public AuthenticatedUser parseAndValidate(String token, Instant now) {
        if (token == null || token.isBlank()) {
            throw new InvalidAccessTokenException("Access token is missing");
        }
        if (now == null) {
            throw new IllegalArgumentException("Now cannot be null");
        }

        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.HS256.equals(signedJwt.getHeader().getAlgorithm())) {
                throw new InvalidAccessTokenException("Access token algorithm is invalid");
            }
            if (!signedJwt.verify(verifier)) {
                throw new InvalidAccessTokenException("Access token signature is invalid");
            }

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            validateClaims(claims, now);

            return new AuthenticatedUser(
                    UUID.fromString(readRequiredStringClaim(claims, "sub")),
                    UUID.fromString(readRequiredStringClaim(claims, "tenantId")),
                    UserRole.valueOf(readRequiredStringClaim(claims, "role"))
            );
        } catch (java.text.ParseException e) {
            throw new InvalidAccessTokenException("Access token is malformed");
        } catch (JOSEException e) {
            throw new InvalidAccessTokenException("Access token signature is invalid");
        } catch (IllegalArgumentException e) {
            throw new InvalidAccessTokenException("Access token claims are invalid");
        }
    }

    private void validateClaims(JWTClaimsSet claims, Instant now) {
        if (!issuer.equals(claims.getIssuer())) {
            throw new InvalidAccessTokenException("Access token issuer is invalid");
        }
        if (claims.getAudience() == null || !claims.getAudience().contains("reqflow-api")) {
            throw new InvalidAccessTokenException("Access token audience is invalid");
        }
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null) {
            throw new InvalidAccessTokenException("Access token claim 'exp' is invalid");
        }
        if (expirationTime.toInstant().plusSeconds(clockSkewSeconds).isBefore(now)) {
            throw new InvalidAccessTokenException("Access token has expired");
        }
        Date notBeforeTime = claims.getNotBeforeTime();
        if (notBeforeTime != null && notBeforeTime.toInstant().minusSeconds(clockSkewSeconds).isAfter(now)) {
            throw new InvalidAccessTokenException("Access token is not active yet");
        }
    }

    private String readRequiredStringClaim(JWTClaimsSet claims, String name) {
        try {
            String value = claims.getStringClaim(name);
            if (value == null || value.isBlank()) {
                throw new InvalidAccessTokenException("Access token claim '" + name + "' is invalid");
            }
            return value;
        } catch (java.text.ParseException e) {
            throw new InvalidAccessTokenException("Access token claim '" + name + "' is invalid");
        }
    }
}
