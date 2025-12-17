package com.security.services;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
public class SecurityConfig {


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
                        .anyRequest().permitAll()
                )
                .csrf(csrf -> csrf.disable()).headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.disable())
                ); // Only for development!
        return http.build();
    }
}
