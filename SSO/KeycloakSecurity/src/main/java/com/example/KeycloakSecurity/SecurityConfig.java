package com.example.KeycloakSecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.util.function.Consumer;

@Configuration
public class SecurityConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        http.csrf(csrf -> csrf.disable())
                //.cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/","logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2.defaultSuccessUrl("/Default", true)
                        .failureUrl("/Default")
                        .failureHandler(customAuthenticationFailureHandler())
                        .authorizationEndpoint(authorization->authorization.authorizationRequestResolver(authorizationRequestResolver(this.clientRegistrationRepository)))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(new CustomOAuth2UserService()))
                )
                .logout(logout -> logout
                        .logoutUrl("/aiv/*/logout")
                        .invalidateHttpSession(true) // Invalidate the session
                        .clearAuthentication(true) // Clear authentication
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());

        return authorizationRequestResolver;
    }

    /*@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:9222"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }*/

    /*@Bean
    public LogoutSuccessHandler keycloakLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            // Redirect to Keycloak logout
            String redirectUri = URLEncoder.encode("http://localhost:9222/aiv", StandardCharsets.UTF_8);
            String logoutUrl = "http://localhost:8280/realms/Default/protocol/openid-connect/logout" + "?redirect_uri=" + redirectUri;

            // If you have the ID token, you can add it as a hint
            if (authentication != null && authentication.getPrincipal() instanceof OAuth2User) {
                OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                if (oauth2User.getAttributes().containsKey("id_token")) {
                    logoutUrl += "&id_token_hint=" + oauth2User.getAttribute("id_token");
                }
            }

            response.sendRedirect(logoutUrl);
        };
    }*/

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return customizer -> customizer.additionalParameters(params -> {
            // Set the prompt parameter to "login" to force the user to log in, otherwise
            // user will auto consent if Logto has a valid session
            params.put("prompt", "login");
        });
    }

    private AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();  // Return the custom failure handler
    }

}

