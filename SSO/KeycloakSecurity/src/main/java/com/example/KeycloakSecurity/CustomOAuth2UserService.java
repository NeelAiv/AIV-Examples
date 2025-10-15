package com.example.KeycloakSecurity;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        // Load user information from the default implementation (which typically pulls from user info endpoint)
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Get the access token
        OAuth2AccessToken accessToken = userRequest.getAccessToken();

        // Copy the existing attributes into a new modifiable map
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());

        // Extract the identity_provider claim from the access token
        Map<String, Object> tokenClaims = extractAllClaimsFromToken(accessToken);
        if (tokenClaims != null) {
            attributes.putAll(tokenClaims); // Merge token claims into the user attributes
        }

        // Return a new DefaultOAuth2User with the updated attributes
        return new DefaultOAuth2User(oAuth2User.getAuthorities(), attributes, "sub");
    }

    private  Map<String, Object> extractAllClaimsFromToken(OAuth2AccessToken accessToken) {
        try {
            // Parse the access token as a JWT
            JWT jwt = JWTParser.parse(accessToken.getTokenValue());

            // Get the claims from the JWT
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();

            // Return all claims as a Map
            return claimsSet.getClaims();
        } catch (ParseException e) {
            e.printStackTrace(); // Handle the parsing error
            return null;
        }
    }
}
