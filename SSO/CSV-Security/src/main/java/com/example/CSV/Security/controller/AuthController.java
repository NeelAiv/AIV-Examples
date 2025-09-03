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

import java.util.*;

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
            String token = jwtTokenUtil.generateToken(parsedUsername, "-1");

            Map<String, Object> ssoPayloadObject = new HashMap<>();

            ssoPayloadObject.put("owner", canonicalUsername);
            ssoPayloadObject.put("traceid", UUID.randomUUID().toString());
            ssoPayloadObject.put("userName", canonicalUsername);
            ssoPayloadObject.put("token", token);
            ssoPayloadObject.put("dc", deptCode);

            HeaderSecurity headerSecurity = new HeaderSecurity();
            String finalRedirectUrl = headerSecurity.getSecure(ssoPayloadObject, deptCode, request, null, UUID.randomUUID().toString());

            return "redirect:" + finalRedirectUrl;

        } else {
            return "redirect:" + request.getContextPath() + "/login?error=true";
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