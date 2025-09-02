package com.example.CSV.Security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // You can use this filter chain for custom requests
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> auth
//                        // Add the new endpoints to the permitAll list
//                        .requestMatchers("/", "/login", "/login-handler", "/success", "/authenticate", "/decode", "/*.html", "/*/sso_login").permitAll()
//                        .requestMatchers(request -> request.getParameter("e") != null).permitAll()
//                        .requestMatchers("/js/**", "/css/**", "/images/**", "/assets/**", "/webjars/**").permitAll()
//                        .anyRequest().authenticated()
//                );
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                );

        return http.build();
    }
}