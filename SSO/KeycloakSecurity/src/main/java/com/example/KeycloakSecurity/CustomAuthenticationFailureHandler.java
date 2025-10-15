package com.example.KeycloakSecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        // You can customize this to redirect anywhere you'd like
        String redirectUrl = "/Default";  // Redirect to /Default on failure

        // Set the redirect URL after the failure
        setDefaultFailureUrl(redirectUrl);

        // Call the parent handler
        super.onAuthenticationFailure(request, response, exception);
    }
}
