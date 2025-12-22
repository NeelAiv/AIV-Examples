package com.example.SAMLwOkta.service;

import com.aivhub.security.HeaderSecurity;
import com.aivhub.security.IAuthentication;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class SamlAuthenticationSuccessHandler2 implements AuthenticationSuccessHandler {
    private final JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();

    @Value("${aiv.sso.test-redirect-base-url:#{null}}")
    private String testRedirectBaseUrl;

    @Value("${saml.attribute.mapping.username}")
    private String usernameAttribute;
    @Value("${saml.attribute.mapping.firstname}")
    private String firstnameAttribute;
    @Value("${saml.attribute.mapping.lastname}")
    private String lastnameAttribute;
    @Value("${saml.attribute.mapping.email}")
    private String emailAttribute;
    @Value("${saml.attribute.mapping.department}")
    private String departmentAttribute;

    public SamlAuthenticationSuccessHandler2() {
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authenticationResult) throws IOException, ServletException {

        IAuthentication authentication = SamlAuthenticationImpl2.getInstance();
        if (authentication == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication service is not available.");
            return;
        }

        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authenticationResult.getPrincipal();

        Map<String, String> attributeMappings = new HashMap<>();
        attributeMappings.put("username", usernameAttribute);
        attributeMappings.put("firstName", firstnameAttribute);
        attributeMappings.put("lastName", lastnameAttribute);
        attributeMappings.put("email", emailAttribute);
        attributeMappings.put("department", departmentAttribute);

        System.out.println("Attribute mappings: " + attributeMappings);

        String department = "Default";
        String aivUsername = getFirstAttribute(principal, attributeMappings.get("username"), null);

        if (aivUsername == null) {
            System.err.println("FATAL: Username attribute not found in SAML assertion. Cannot proceed.");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Username not found in SAML assertion.");
            return;
        }

        System.out.println("SAML login successful for user: " + aivUsername);

        try {
            new HeaderSecurity().createFilesFolders(aivUsername, department, "SAML_PROVISIONING");
        } catch (Exception e) {
            System.err.println("CRITICAL ERROR: Failed to create home folder for user " + aivUsername + ".");
            e.printStackTrace();
        }

        Map<String, Object> credentials = new HashMap<>();
        credentials.put("userName", aivUsername);
        credentials.put("firstName", getFirstAttribute(principal, attributeMappings.get("firstName"), ""));
        credentials.put("lastName", getFirstAttribute(principal, attributeMappings.get("lastName"), ""));
        credentials.put("email", getFirstAttribute(principal, attributeMappings.get("email"), ""));
        credentials.put("department", department);
        System.out.println("User Details/credentials in buildAivUserFromSaml: " + credentials);

        Map<String, Object> userDetails = authentication.authenticate(credentials);

        System.out.println("User Details here: " + userDetails);

        if (userDetails != null && userDetails.containsKey("token")){
            System.out.println("Authentication successful for user: " + aivUsername);

            String canonicalUsername = userDetails.get("userName").toString();
            String deptCode = userDetails.get("deptCode").toString();
            System.out.println("can user name: " + canonicalUsername);
            System.out.println("deptCode after can user name: " + deptCode);

            String token = userDetails.get("token").toString();

            Map<String, Object> ssoPayloadObject = new HashMap<>();

            ssoPayloadObject.put("owner", canonicalUsername);
            ssoPayloadObject.put("traceid", UUID.randomUUID().toString());
            ssoPayloadObject.put("userName", canonicalUsername);
            ssoPayloadObject.put("token", token);
            ssoPayloadObject.put("deptCode", deptCode);
            ssoPayloadObject.put("dc", deptCode);

            System.out.println("SSO payload here: " + ssoPayloadObject);

            HeaderSecurity headerSecurity = new HeaderSecurity();
            String finalRedirectUrl = headerSecurity.getSecure(ssoPayloadObject, deptCode, request, null, UUID.randomUUID().toString());
            System.out.println("Final redirect url here: " + finalRedirectUrl);
            response.sendRedirect(finalRedirectUrl);

        } else {
            System.err.println("Authentication failed or the userDetails map did not contain a token.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed during post-processing.");
        }
    }

    private String getFirstAttribute(Saml2AuthenticatedPrincipal principal, String attributeName, String defaultValue) {
        List<Object> values = principal.getAttribute(attributeName);
        return (values != null && !values.isEmpty()) ? values.get(0).toString() : defaultValue;
    }
}