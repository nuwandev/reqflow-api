package com.nuwandev.reqflowapi.identity.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class AuthConfiguration {

    @Bean
    Clock systemClock() {
        return Clock.systemUTC();
    }
}
