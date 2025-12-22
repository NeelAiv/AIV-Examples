package com.example.SAMLwOkta.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Service
public class OktaService {

    private final RestTemplate restTemplate;
    private final String oktaApiToken;
    private final String oktaDomain;

    public OktaService(RestTemplate restTemplate,
                       @Value("${okta.api.token}") String oktaApiToken,
                       @Value("${okta.api.domain}") String oktaDomain) {
        this.restTemplate = restTemplate;
        this.oktaApiToken = oktaApiToken;
        this.oktaDomain = oktaDomain;
    }

    private HttpEntity<String> createHttpEntity() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "SSWS " + oktaApiToken);
        headers.set("Accept", "application/json");
        return new HttpEntity<>(headers);
    }

    public List<Map<String, Object>> getAllUsers() {
        String url = "https://" + oktaDomain + "/api/v1/users";
        try {
            ParameterizedTypeReference<List<Map<String, Object>>> typeRef = 
                new ParameterizedTypeReference<List<Map<String, Object>>>() {};
            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url, HttpMethod.GET, createHttpEntity(), typeRef);
            return response.getBody() != null ? response.getBody() : List.of();
        } catch (Exception e) {
            System.err.println("WARN: Failed to fetch users from Okta API: " + e.getMessage());
            return List.of();
        }
    }

    public Map<String, Object> getUserByName(String username) {
        String url = "https://" + oktaDomain + "/api/v1/users/" + username;
        try {
            ParameterizedTypeReference<Map<String, Object>> typeRef = 
                new ParameterizedTypeReference<Map<String, Object>>() {};
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.GET, createHttpEntity(), typeRef);
            return response.getBody();
        } catch (Exception e) {
            return null;
        }
    }

}
