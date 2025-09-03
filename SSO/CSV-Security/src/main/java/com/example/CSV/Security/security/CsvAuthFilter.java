package com.example.CSV.Security.security;

import com.aivhub.security.HeaderSecurity;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Order(1)
public class CsvAuthFilter implements Filter {

    private static final Pattern AIV_ENTRY_PATTERN = Pattern.compile("^/aiv/[a-zA-Z0-9_]+/?$");

    JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();

    private static final Set<String> EXCLUDED_PATHS = new HashSet<>(Arrays.asList(
            "/aiv/login",
            "/aiv/login-handler",
            "/aiv/authenticate",
            "/aiv/decode",
            "/aiv/success"
    ));


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String uri = req.getRequestURI();

        if (isExcluded(uri)) {
            chain.doFilter(request, response);
            return;
        }

        handleTokenExtensionForSpecialUrls(req, res, uri);

        Matcher matcher = AIV_ENTRY_PATTERN.matcher(uri);
        if (matcher.matches() && req.getParameter("e") == null) {
            String contextPath = req.getContextPath();
            res.sendRedirect(contextPath + "/login");
            return;
        }

        chain.doFilter(request, response);
    }

    private void handleTokenExtensionForSpecialUrls(HttpServletRequest req, HttpServletResponse res, String uri) {
        if (shouldExtendTokenForUri(uri)) {
            String oldToken = req.getHeader("token");
            if (oldToken == null) {
                oldToken = req.getParameter("token");
            }

            if (oldToken != null && !oldToken.trim().isEmpty()) {
                try {

                    int sessionTimeInMinutes = getSessionTime();
                    int sessionTimeInSeconds = sessionTimeInMinutes * 60;

                    String extendedToken = jwtTokenUtil.extendTokenExpiration(oldToken, sessionTimeInSeconds);

                    res.addHeader("token", extendedToken);
                } catch (Exception e) {
                    System.err.println("ERROR: Failed to extend token for URL " + uri + ": " + e.getMessage());
                    try {
                        res.getWriter().print("Session Expired");
                    } catch (IOException ioException) {
                        System.err.println("ERROR: Could not write session expired message: " + ioException.getMessage());
                    }
                    return;
                }
            }
        }
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
            return 3600;
        }
    }

    private boolean isExcluded(String uri) {
        if (uri.startsWith("/aiv/") && (uri.endsWith(".css") || uri.endsWith(".js") || uri.endsWith(".html"))) {
            // A simple check to see if it's trying to access the login page itself.
            return uri.equals("/aiv/login.html");
        }
        return EXCLUDED_PATHS.contains(uri);
    }
}
