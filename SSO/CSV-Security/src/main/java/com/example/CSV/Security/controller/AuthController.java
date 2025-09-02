package com.example.CSV.Security.controller;

import com.aivhub.security.HeaderSecurity;
import com.aivhub.security.IAuthentication;
import com.example.CSV.Security.security.CsvAuthenticationImpl;
import com.example.CSV.Security.security.JwtTokenUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
public class AuthController {

    private final JwtTokenUtil jwtTokenUtil;
    private final ObjectMapper objectMapper;

    public AuthController() {
        this.objectMapper = new ObjectMapper();
        this.jwtTokenUtil =  new JwtTokenUtil();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }


    @PostMapping("/login-handler")
    public String handleLogin(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request) throws Exception {

        IAuthentication authentication = CsvAuthenticationImpl.getInstance();
        if (authentication == null) {
            System.err.println("FATAL: Authentication service is not available.");
            return "redirect:" + request.getContextPath() + "/login?error=true";
        }

        String deptCode = "Default";
        String parsedUsername = username;

        if(username.contains("::")){
            String[] parts = username.split("::", 2);
            if (parts.length == 2){
                deptCode = parts[0];
                parsedUsername = parts[1];
            }
        }

        Map<String, Object> credentials = Map.of("userName", parsedUsername, "password", password, "deptCode", deptCode);

        Map<String, Object> userDetails = authentication.authenticate(credentials);

        if (userDetails != null) {
            String canonicalUsername = userDetails.get("userName").toString();

            String salt = "Activeintelligence";
            String token = jwtTokenUtil.generateToken(parsedUsername, "-1");

            Map<String, Object> ssoPayloadObject = new HashMap<>();


            ssoPayloadObject.put("owner", canonicalUsername);
            ssoPayloadObject.put("traceid", UUID.randomUUID().toString());
            ssoPayloadObject.put("password", password);
            ssoPayloadObject.put("salt", salt);
            ssoPayloadObject.put("userName", canonicalUsername);
            ssoPayloadObject.put("token", token);
            ssoPayloadObject.put("auth-token", token);
            ssoPayloadObject.put("archiveMode", false);
            ssoPayloadObject.put("additional_token", new HashMap<>());
            ssoPayloadObject.put("deptCode", deptCode);
            ssoPayloadObject.put("dc", deptCode);
            ssoPayloadObject.put("additionalHeaders", new HashMap<>());
            ssoPayloadObject.put("username", canonicalUsername);


            HeaderSecurity headerSecurity = new HeaderSecurity();
            String hexPayload = headerSecurity.getSecure(ssoPayloadObject, deptCode, UUID.randomUUID().toString());

            String finalRedirectUrl = getString(request, deptCode, hexPayload);

            return "redirect:" + finalRedirectUrl;

        } else {
            return "redirect:" + request.getContextPath() + "/login?error=true";
        }
    }

    private static String getString(HttpServletRequest request, String deptCode, String hexPayload) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();

        return String.format("%s://%s:%d%s/%s/sso_login?e=%s",
                scheme,
                serverName,
                serverPort,
                contextPath,
                deptCode,
                hexPayload
        );
    }

    @PostMapping("/authenticate")
    @ResponseBody
    public ResponseEntity<String> authenticateApi(@RequestBody Map<String, Object> credentials) throws Exception {
        IAuthentication authentication = CsvAuthenticationImpl.getInstance();
        if (authentication == null) {
            return ResponseEntity.status(500).body("Authentication service not initialized.");
        }

        String traceId = UUID.randomUUID().toString();
        String deptCode = (String) credentials.get("deptCode");
        String userName = (String) credentials.get("userName");
        String password = (String) credentials.get("password");

        Map<String, Object> userDetails = authentication.authenticate(credentials);

        if (userDetails != null) {
            String canonicalUsername = userDetails.get("userName").toString();
            String salt = "Activeintelligence";
            String token = jwtTokenUtil.generateToken(canonicalUsername, "-1");

            Map<String, Object> ssoPayload = new HashMap<>();
            ssoPayload.put("owner", canonicalUsername);
            ssoPayload.put("traceid", UUID.randomUUID().toString());
            ssoPayload.put("salt", salt);
            ssoPayload.put("isAdmin", canonicalUsername.equalsIgnoreCase("admin"));
            ssoPayload.put("userName", canonicalUsername);
            ssoPayload.put("additional_token", new HashMap<>());
            ssoPayload.put("archiveMode", false);
            ssoPayload.put("token", token);
            ssoPayload.put("isDatasource", true);
            ssoPayload.put("password", password);
            ssoPayload.put("deptCode", deptCode);
            ssoPayload.put("auth-token", token);
            ssoPayload.put("username", canonicalUsername);
            ssoPayload.put("additionalHeaders", new HashMap<>());
            ssoPayload.put("dc", deptCode);

            HeaderSecurity headerSecurity = new HeaderSecurity();
            String securePayload = headerSecurity.getSecure(ssoPayload, deptCode, UUID.randomUUID().toString());

            return ResponseEntity.ok(securePayload);
        } else {
            return ResponseEntity.status(401).body("Invalid Authentication");
        }
    }

    @PostMapping("/decode")
    public ResponseEntity<String> decodePayload(@RequestBody String hexPayload) {
        try {
            String decodedJsonString = fromHexString(hexPayload);
            Object jsonObject = objectMapper.readValue(decodedJsonString, Object.class);
            String prettyJson = objectMapper.writeValueAsString(jsonObject);
            return ResponseEntity.ok(prettyJson);
        } catch (JsonProcessingException e) {
            return ResponseEntity.badRequest().body("Error: Invalid JSON format after decoding.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: Invalid hex string provided. " + e.getMessage());
        }
    }

    private String fromHexString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String s = hex.substring(i, i + 2);
            str.append((char) Integer.parseInt(s, 16));
        }
        return str.toString();
    }
}