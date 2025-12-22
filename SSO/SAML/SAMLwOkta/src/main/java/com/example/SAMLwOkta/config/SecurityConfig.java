package com.example.AIVsaml.config;

//import com.example.AIVsaml.SamlAuthenticationSuccessHandler;
import com.example.AIVsaml.SamlAuthenticationSuccessHandler2;
import com.example.AIVsaml.SamlInitiationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;


import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final SamlAuthenticationSuccessHandler2 samlAuthenticationSuccessHandler;
    private final SamlInitiationFilter samlInitiationFilter;

    @Value("${aiv.sso.post-logout-redirect-uri}")
    private String postLogoutRedirectUri;


    public SecurityConfig(SamlAuthenticationSuccessHandler2 samlAuthenticationSuccessHandler, SamlInitiationFilter samlInitiationFilter) {
        this.samlAuthenticationSuccessHandler = samlAuthenticationSuccessHandler;
        this.samlInitiationFilter = samlInitiationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(this.samlInitiationFilter, AuthorizationFilter.class)
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/aiv/v5/api/logout").permitAll()
                        .requestMatchers("/", "/login","/decode","/index.html", "/assets/**", "/saml2/**", "/login/saml2/sso/**", "/authenticate", "/aiv/**/*.js", "/aiv/**/*.css", "/*/postuserinfo", "/*/sso_login").permitAll()
                        .anyRequest().permitAll()
                )
                .saml2Login(saml2 -> saml2
                        .successHandler(this.samlAuthenticationSuccessHandler)
                )
                .logout(logout ->
                        logout
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                                .logoutSuccessUrl(postLogoutRedirectUri)
                )
                .saml2Logout(withDefaults());
        return http.build();
    }

}