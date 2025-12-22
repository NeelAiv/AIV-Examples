package com.example.SAMLwOkta.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class JwtTokenUtil {
    private static final Key SECRET_KEY;

    static {
        SecretKey tempKey = null;
        try {
            ClassPathResource resource = new ClassPathResource("token");
            Reader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8);
            String base64Key = FileCopyUtils.copyToString(reader).trim();
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);
            tempKey = new SecretKeySpec(decodedKey, SignatureAlgorithm.HS256.getJcaName());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read the '/token' file", e);
        }
        SECRET_KEY = tempKey;
    }

    public String generateToken(String username, String time) {
        Date now = new Date();
        long expirationMillis;

        if ("-1".equals(time)) {
            expirationMillis = TimeUnit.HOURS.toMillis(24);
        } else {
            try {
                expirationMillis = Long.parseLong(time) * 60 * 1000;
            } catch (NumberFormatException e) {
                expirationMillis = 20 * 60 * 1000;
            }
        }

        Date expiration = new Date(now.getTime() + expirationMillis);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(SECRET_KEY)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String extendTokenExpiration(String token, int extensionTimeInSeconds) throws Exception {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            Date issuedAt = claims.getIssuedAt();

            Date now = new Date();
            Date newExpiration = new Date(now.getTime() + (extensionTimeInSeconds * 1000L));

            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(issuedAt != null ? issuedAt : now)
                    .setExpiration(newExpiration)
                    .signWith(SECRET_KEY)
                    .compact();

        } catch (Exception e) {
            System.err.println("Failed to extend token expiration: " + e.getMessage());
            throw new Exception("Invalid or expired token", e);
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            System.err.println("Failed to extract username from token: " + e.getMessage());
            return null;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Date expiration = claims.getExpiration();
            return expiration != null && expiration.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }
}

