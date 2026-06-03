package com.nuwandev.reqflowapi.identity.application.service;

import com.nuwandev.reqflowapi.identity.application.port.input.AuthTokens;
import com.nuwandev.reqflowapi.identity.application.port.input.LoginCommand;
import com.nuwandev.reqflowapi.identity.application.port.output.JwtPort;
import com.nuwandev.reqflowapi.identity.domain.port.PasswordHasherPort;
import com.nuwandev.reqflowapi.identity.domain.port.RefreshTokenGenerator;
import com.nuwandev.reqflowapi.identity.domain.port.TokenHasher;
import com.nuwandev.reqflowapi.identity.domain.service.LoginPolicy;
import com.nuwandev.reqflowapi.identity.domain.exception.InvalidCredentialsException;
import com.nuwandev.reqflowapi.identity.domain.model.User;
import com.nuwandev.reqflowapi.identity.domain.model.UserRole;
import com.nuwandev.reqflowapi.identity.domain.repository.AuthSessionRepository;
import com.nuwandev.reqflowapi.identity.domain.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginService")
class LoginServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final long TTL_SECONDS = 2592000L;

    @Mock private UserRepository userRepo;
    @Mock private AuthSessionRepository sessionRepo;
    @Mock private PasswordHasherPort passwordHasher;
    @Mock private JwtPort jwtPort;
    @Mock private RefreshTokenGenerator tokenGenerator;
    @Mock private TokenHasher tokenHasher;

    private LoginService service;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        Clock fixedClock = Clock.fixed(NOW, ZoneOffset.UTC);
        LoginPolicy loginPolicy = new LoginPolicy(passwordHasher);
        service = new LoginService(
                userRepo, sessionRepo, loginPolicy, jwtPort,
                tokenGenerator, tokenHasher, fixedClock, TTL_SECONDS
        );
        tenantId = UUID.randomUUID();
    }

    @Test
    @DisplayName("should login successfully with valid credentials")
    void loginSuccessful() {
        String email = "test@example.com";
        String password = "password";
        String hash = "hashed-password";
        User user = User.reconstruct(
                UUID.randomUUID(), tenantId, email, hash,
                "Test User", UserRole.REQUESTOR, true,
                NOW.minusSeconds(100), NOW.minusSeconds(100)
        );

        when(userRepo.findByEmail(tenantId, email)).thenReturn(Optional.of(user));
        when(passwordHasher.matches(password, hash)).thenReturn(true);
        when(tokenGenerator.generate()).thenReturn("raw-refresh");
        when(tokenHasher.hash("raw-refresh")).thenReturn("hashed-refresh");
        when(jwtPort.generateAccessToken(eq(tenantId), eq(user), eq(NOW))).thenReturn("access-jwt");

        LoginCommand command = new LoginCommand(tenantId, email, password, "127.0.0.1", "Agent");
        AuthTokens result = service.execute(command);

        assertThat(result.accessToken()).isEqualTo("access-jwt");
        assertThat(result.refreshToken()).isEqualTo("raw-refresh");
        verify(sessionRepo).save(any());
    }

    @Test
    @DisplayName("should throw InvalidCredentialsException if user not found")
    void userNotFound() {
        String email = "unknown@example.com";
        when(userRepo.findByEmail(tenantId, email)).thenReturn(Optional.empty());

        LoginCommand command = new LoginCommand(tenantId, email, "password", null, null);
        
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    @DisplayName("should throw InvalidCredentialsException if password does not match")
    void passwordMismatch() {
        String email = "test@example.com";
        String password = "wrong";
        String hash = "hashed-password";
        User user = User.reconstruct(
                UUID.randomUUID(), tenantId, email, hash,
                "Test User", UserRole.REQUESTOR, true,
                NOW.minusSeconds(100), NOW.minusSeconds(100)
        );

        when(userRepo.findByEmail(tenantId, email)).thenReturn(Optional.of(user));
        when(passwordHasher.matches(password, hash)).thenReturn(false);

        LoginCommand command = new LoginCommand(tenantId, email, password, null, null);
        
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(InvalidCredentialsException.class);
    }
}
