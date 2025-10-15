package com.example.KeycloakSecurity;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.IAuthentication;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

public class CommonUtility {

    public Map<String, Object> checkUser(Map<String,Object> data, String department, String traceid, IAuthentication i) {
        try {
            String userId = data.get("userName").toString();
            Map<String, Object> userDetails = new HashMap<>();

            if (!i.isUserExists(userId, department)) {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, this.getClass().getName(), "User not found, creating new user: " + userId,
                        traceid, department, null);

                Map<String, Object> newUserPayload = new HashMap<>();
                newUserPayload.put("firstName", data.get("firstName"));
                newUserPayload.put("lastName", data.get("lastName"));
                newUserPayload.put("userName", userId);
                newUserPayload.put("email", data.get("email"));

                i.CreateEditUser(newUserPayload, department);

                Map<String, Object> roleData = new HashMap<>();
                roleData.put("roles", "default-user");
                roleData.put("userName", userId);
                i.updateRolesForUser(roleData, "system", department, traceid);

                userDetails.putAll(newUserPayload);

            } else {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, this.getClass().getName(), "Existing user found: " + userId,
                        traceid, department, null);
                Map<String,Object> existingUser = i.getUserByName(userId, department, null);
                if (existingUser != null) {
                    userDetails.putAll(existingUser);
                }
            }

            Map<String, Object> finalUserData = new HashMap<>();
            finalUserData.put("firstName", userDetails.get("firstName"));
            finalUserData.put("lastName", userDetails.get("lastName"));
            finalUserData.put("userName", userDetails.get("username")); // Keycloak uses 'username'
            finalUserData.put("email", userDetails.get("email"));
            finalUserData.put("department", department);
            finalUserData.put("deptCode", department);

            return finalUserData;

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(),
                    traceid, department, e);
            return null;
        }
    }

    public static Boolean isAuthneticated(String traceid, String deptCode) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String tokenInfo = null;
            return authentication.isAuthenticated();
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, CommonUtility.class, e.getMessage(), traceid, deptCode, e);
            return false;
        }
    }

    public Map<String, Object> getUserInfo(OAuth2AuthorizedClientService clientService,String deptCode, String traceid) {

        Map<String, Object> obj = new HashMap<String, Object>();

        OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizedClient client =
                clientService.loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());

        String accessToken = getMasterRealmToken(traceid,deptCode);
        DefaultOAuth2User principalObject = authentication != null ? (DefaultOAuth2User) authentication.getPrincipal() : null;
        String tokenInfo = null;

        if (principalObject.getAttributes().containsKey("given_name")) {
            obj.put("firstName", principalObject.getAttribute("given_name").toString());
        }

        if (principalObject.getAttributes().containsKey("family_name")) {
            obj.put("lastName", principalObject.getAttribute("family_name").toString());
        }


        if (principalObject.getAttributes().containsKey("identity_provider")) {
            obj.put("identity_provider", principalObject.getAttribute("identity_provider").toString());
        }

        String username = principalObject.getAttribute("preferred_username");
        obj.put("userName", username);

        obj.put("email", principalObject.getAttribute("email"));

        return obj;
    }


    public String getMasterRealmToken(String traceid, String deptCode) {

        try {

            if (GetBean.adminLogin.containsKey("access_token") && GetBean.adminLogin.get("access_token") != null) {
                return GetBean.adminLogin.get("access_token").toString();
            } else {
                InputStream inputStream = Files.newInputStream(Paths.get( GetBean.REPOSITORYLOCATION_PATH+"/econfig/superuser.properties"));

                Properties p = new Properties();
                p.load(inputStream);
                RestUtils rs = new RestUtils();

                Map<String, Object> data = new HashMap<>();

                Iterator<Object> it = p.keySet().iterator();

                while (it.hasNext()) {
                    String propName = it.next().toString();
                    if (!it.equals("url")) {
                        data.put(propName, p.get(propName));
                    }
                }


                String resp = rs.encodedUrl((GetBean.keycloakUrl.endsWith("/") ? GetBean.keycloakUrl : (GetBean.keycloakUrl + "/")) + p.get("url").toString(), data, traceid);

                final Map<String, Object> _pD = resp != null ? new ObjectMapper().readValue(resp, new TypeReference<Map<String, Object>>() {
                }) : null;

                GetBean.adminLogin.put("access_token", _pD != null && _pD.containsKey("access_token") ? _pD.get("access_token").toString() : null);
                GetBean.adminLogin.put("refresh_token", _pD != null && _pD.containsKey("refresh_token") ? _pD.get("refresh_token").toString() : null);
                return _pD != null && _pD.containsKey("access_token") ? _pD.get("access_token").toString() : null;
            }

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), traceid, deptCode, e);
            return null;
        }


    }

    public String fromHexString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return str.toString();
    }

}
