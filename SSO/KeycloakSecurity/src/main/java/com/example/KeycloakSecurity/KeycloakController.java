package com.example.KeycloakSecurity;

import com.aivhub.logs.AuditLoggerUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/")
@Component
public class KeycloakController {

    @Autowired
    OAuth2AuthorizedClientService clientService;

    @GetMapping("/Default")
    public String showSuccessPage(@AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            String name = principal.getAttribute("name");
            String email = principal.getAttribute("email");
            String username = principal.getAttribute("preferred_username");

            return String.format("<h1>Login Successful!</h1>" +
                    "<h2>Hello, %s!</h2>" +
                    "<p>Welcome to the application.</p>" +
                    "<p>Your Username is: %s</p>" +
                    "<p>Your Email is: %s</p>" +
                    "<br><br><a href=\"/aivo/logut\">Logout</a>", name, username, email);
        } else {
            return "<h1>Login Successful!</h1><p>Welcome, but user details are not available.</p>";
        }
    }

    @PostMapping(path = "/{dept}/logout", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView logoutAIV(HttpServletRequest sp, HttpServletResponse sr, HttpSession session, @PathVariable String dept, @RequestHeader(required = false, name = "traceid", defaultValue = "") String traceid) {
        try {

            String keycloakLogoutUrl = (GetBean.keycloakUrl.endsWith("/") ? GetBean.keycloakUrl : (GetBean.keycloakUrl + "/"))+ "/realms/"+dept+"/protocol/openid-connect/logout";
            logout(new HashMap<>(), keycloakLogoutUrl, traceid, dept, "post");

            new SecurityContextLogoutHandler().logout(sp, sr, SecurityContextHolder.getContext().getAuthentication());
            SecurityContextHolder.clearContext();



            sp.getSession().invalidate();
            sp.logout();
            return new RedirectView(GetBean.gatewayApp + "/Default");
            //return new RedirectView(OidcLogtoApplication.gatewayApp + "/" + dept);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(),traceid,dept, e);
            return null;
        }
    }


    public String logout(Map<String, Object> headers, String url, String traceid, String deptCode, String type) {
        try {
            OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            OAuth2AuthorizedClient client =
                    clientService.loadAuthorizedClient(
                            authentication.getAuthorizedClientRegistrationId(),
                            authentication.getName());

            String accessToken = client.getAccessToken().getTokenValue();
            String refreshToken = client.getRefreshToken().getTokenValue();
            headers.put("Authorization", "Bearer " + accessToken);
            RestUtils rs = new RestUtils();




            List<Map<String, Object>> body = new ArrayList<>();
            Map<String, Object> data = new HashMap<>();
            data.put("refresh_token", refreshToken);
            data.put("client_id", client.getClientRegistration().getClientId());
            data.put("client_secret", client.getClientRegistration().getClientSecret());
            data.put("Authorization", "Bearer " + accessToken);

            body.add(data);

            String res = rs.encodedUrl(url, data, traceid);

            return "done";
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), traceid, deptCode, e);
            return null;
        }

    }

}
