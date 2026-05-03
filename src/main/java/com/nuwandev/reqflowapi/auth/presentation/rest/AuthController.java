package com.nuwandev.reqflowapi.auth.presentation.rest;

import com.nuwandev.reqflowapi.auth.presentation.rest.dto.AuthTokenResponse;
import com.nuwandev.reqflowapi.auth.presentation.rest.dto.LoginRequest;
import com.nuwandev.reqflowapi.auth.presentation.rest.dto.MeResponse;
import com.nuwandev.reqflowapi.auth.application.port.input.AuthTokens;
import com.nuwandev.reqflowapi.auth.application.port.input.LoginCommand;
import com.nuwandev.reqflowapi.auth.application.port.input.LoginUseCase;
import com.nuwandev.reqflowapi.auth.application.port.input.LogoutCommand;
import com.nuwandev.reqflowapi.auth.application.port.input.LogoutUseCase;
import com.nuwandev.reqflowapi.auth.application.port.input.RefreshTokenCommand;
import com.nuwandev.reqflowapi.auth.application.port.input.RefreshTokenUseCase;
import com.nuwandev.reqflowapi.auth.application.port.output.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Validated
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final LoginUseCase loginUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;
    private final LogoutUseCase logoutUseCase;
    private final AuthContext authContext;
    private final long refreshTokenTtlSeconds;

    public AuthController(
            LoginUseCase loginUseCase,
            RefreshTokenUseCase refreshTokenUseCase,
            LogoutUseCase logoutUseCase,
            AuthContext authContext,
            @Value("${auth.refresh-token-ttl-seconds:2592000}") long refreshTokenTtlSeconds
    ) {
        this.loginUseCase = loginUseCase;
        this.refreshTokenUseCase = refreshTokenUseCase;
        this.logoutUseCase = logoutUseCase;
        this.authContext = authContext;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    @PostMapping("/login")
    public AuthTokenResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        AuthTokens tokens = loginUseCase.execute(new LoginCommand(
                request.tenantId(),
                request.email(),
                request.password(),
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent")
        ));

        // Set refresh token in HttpOnly cookie (controller is responsible for transport concerns)
        String cookieValue = tokens.refreshToken();
        String cookie = String.format(
                "reqflow_refresh=%s; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth; Max-Age=%d",
                cookieValue,
                refreshTokenTtlSeconds
        );
        httpResponse.addHeader("Set-Cookie", cookie);

        return AuthTokenResponse.from(tokens);
    }

    @PostMapping("/refresh")
    public AuthTokenResponse refresh(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        jakarta.servlet.http.Cookie[] cookies = httpRequest.getCookies();
        if (cookies == null) {
            throw new IllegalArgumentException("Missing refresh token cookie");
        }
        String refreshToken = null;
        for (jakarta.servlet.http.Cookie c : cookies) {
            if ("reqflow_refresh".equals(c.getName())) {
                refreshToken = c.getValue();
                break;
            }
        }
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Missing refresh token cookie");
        }

        AuthTokens tokens = refreshTokenUseCase.execute(new RefreshTokenCommand(refreshToken));

        // Set new refresh token in cookie (rotation)
        String cookie = String.format(
                "reqflow_refresh=%s; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth; Max-Age=%d",
                tokens.refreshToken(),
                refreshTokenTtlSeconds
        );
        httpResponse.addHeader("Set-Cookie", cookie);

        return AuthTokenResponse.from(tokens);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletResponse httpResponse) {
        logoutUseCase.execute(new LogoutCommand(
                authContext.currentTenantId(),
                authContext.currentUserId()
        ));

        // Clear the refresh cookie on logout
        String cookie = "reqflow_refresh=; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth; Max-Age=0";
        httpResponse.addHeader("Set-Cookie", cookie);
    }

    @GetMapping("/me")
    public MeResponse me() {
        return new MeResponse(
                authContext.currentUserId(),
                authContext.currentTenantId(),
                authContext.currentRole()
        );
    }

}
