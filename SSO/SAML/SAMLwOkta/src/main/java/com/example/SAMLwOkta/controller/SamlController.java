package com.example.AIVsaml.controller;

import com.example.AIVsaml.SamlAuthenticationImpl2;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

@Controller
public class SamlController {

    private final ObjectMapper objectMapper;

    public SamlController() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @GetMapping("/login")
    public String initiateSamlLogin() {
        return "redirect:/saml2/authenticate/okta";
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