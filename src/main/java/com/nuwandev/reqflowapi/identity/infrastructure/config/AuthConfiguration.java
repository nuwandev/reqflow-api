package com.nuwandev.reqflowapi.identity.infrastructure.config;

import com.nuwandev.reqflowapi.identity.domain.port.PasswordHasherPort;
import com.nuwandev.reqflowapi.identity.domain.service.LoginPolicy;
import com.nuwandev.reqflowapi.identity.domain.service.RefreshTokenPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class AuthConfiguration {

    @Bean
    Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    LoginPolicy loginPolicy(PasswordHasherPort passwordHasher) {
        return new LoginPolicy(passwordHasher);
    }

    @Bean
    RefreshTokenPolicy refreshTokenPolicy(
            @Value("${auth.rotation-grace-period-seconds:15}") long rotationGracePeriodSeconds
    ) {
        return new RefreshTokenPolicy(rotationGracePeriodSeconds);
    }
}
