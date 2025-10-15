package com.example.KeycloakSecurity;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class MyCustomRequestMatcher implements RequestMatcher {

    @Override
    public boolean matches(HttpServletRequest request) {
        try {
            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
