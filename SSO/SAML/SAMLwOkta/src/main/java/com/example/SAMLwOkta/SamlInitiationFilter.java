package com.example.SAMLwOkta;

import com.aivhub.security.HeaderSecurity;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.regex.Pattern;

@Component
@Order(1)
public class SamlInitiationFilter implements Filter {

    private static final Pattern AIV_ENTRY_PATTERN = Pattern.compile("^/aiv/[a-zA-Z0-9_]+/?$");

    @Value("${aiv.sso.post-logout-redirect-uri}")
    private String postLogoutRedirectUri;

    JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {

            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;
            String path = req.getRequestURI();

//            System.out.println("Path here: " + path);

            String contextPath = req.getContextPath();
            String logoutPath = (contextPath + "/").replaceAll("//", "/");
            String errorPath = contextPath + "/error";

            if (path.equals(logoutPath) || path.equals(errorPath)) {
//                System.out.println("SamlInitiationFilter: Ignoring post-logout or error path: " + path);
                chain.doFilter(request, response);
                return;
            }

            if (AIV_ENTRY_PATTERN.matcher(path).matches() && req.getParameter("e") == null
                    && !isFileOperationEndpoint(path)) {
//                System.out.println("SamlInitiationFilter: Intercepted AIV entry point: " + path + ". Redirecting to SAML provider.");

                String relayState = req.getRequestURL().toString();
                if (req.getQueryString() != null) {
                    relayState += "?" + req.getQueryString();
                }

//                System.out.println("Relay State: " + relayState);

                String samlLoginUrl = UriComponentsBuilder.fromPath(req.getContextPath())
                        .path("/saml2/authenticate/okta")
                        .queryParam("RelayState", relayState)
                        .toUriString();

//                System.out.println("Redirecting to SAML IdP with RelayState: " + relayState);
                res.sendRedirect(samlLoginUrl);
                return;
            } try {
                handleCooperativeTokenExtension(req, res);
            } catch (Exception e) {
                System.err.println("Error during token extension: " + e.getMessage());
            }

            chain.doFilter(request, response);
        } catch (Exception e){
//            System.out.println("Failed in do Filter due to " + e.getMessage());
        }

    }

    private void handleCooperativeTokenExtension(HttpServletRequest req, HttpServletResponse res) {
        String uri = req.getRequestURI();

        if (shouldExtendTokenForUri(uri)) {
            String oldToken = null;

            String authHeader = req.getHeader("Authorization");
            if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
                oldToken = authHeader.substring(7);
//                System.out.println("Filter found token in 'Authorization' header.");
            }

            if (oldToken == null) {
                oldToken = req.getHeader("token");
                if (oldToken != null) {
//                    System.out.println("Filter found token in custom 'token' header.");
                }
            }

            if (oldToken != null && !oldToken.trim().isEmpty()) {
                try {
                    if (!res.containsHeader("auth-token") && !res.containsHeader("token")) {

                        int sessionTimeInSeconds = getSessionTime() * 60;

                        String extendedToken = jwtTokenUtil.extendTokenExpiration(oldToken, sessionTimeInSeconds);
                        res.addHeader("auth-token", extendedToken);
//                        System.out.println("SUCCESS: SAML Filter extended token for API call: " + uri);
                    } else {
                        System.out.println("DEBUG: Another filter may have already handled token extension. SAML filter is standing down.");
                    }
                } catch (Exception e) {
                    System.err.println("ERROR: Failed to extend token. It may be invalid or malformed. Error: " + e.getMessage());
                }
            } else {
                System.out.println("DEBUG: No token found in headers for extension on URI: " + uri);
            }
        }
    }

    private boolean isFileOperationEndpoint(String uri) {
        if (uri == null) {
            return false;
        }
        return uri.contains("file_upload_servlet")
                || uri.contains("download_file")
                || uri.contains("download_word_file")
                || uri.contains("export_excel")
                || uri.contains("image_upload_servlet")
                || uri.contains("zip_files")
                || uri.contains("load_document")
                || uri.contains("subreportrun")
                || uri.contains("execute_adhoc_report");
    }

    private boolean shouldExtendTokenForUri(String uri) {
        return uri != null && (uri.contains("/v5") || uri.contains("file_upload_servlet")
                || uri.contains("download_file") || uri.contains("download_word_file")
                || uri.contains("export_excel") || uri.contains("image_upload_servlet")
                || uri.contains("zip_files") || uri.contains("load_document")
                || uri.contains("subreportrun") || uri.contains("execute_adhoc_report"));
    }

    private int getSessionTime() {
        try {
            String sessionTimeStr = new HeaderSecurity().getSessionTime();
            return Integer.parseInt(sessionTimeStr);
        } catch (Exception e) {
            System.out.println("DEBUG: Using default session time due to error: " + e.getMessage());
            return 3600;
        }
    }
}