package com.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtTokenUtil {
    private static long EXPIRATION_TIME = 20 * 60 * 1000; // 20 minutes in milliseconds
    private static final Key SECRET_KEY;

    static {
        SecretKey tempKey = null;
        try {
            // Read the base64-encoded key from the /token file
            String base64Key = IOUtils.toString(new ClassPathResource("/token").getInputStream(), StandardCharsets.UTF_8).trim();

            // Decode the base64 string
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);

            // Create a SecretKey using HMAC SHA-256
            tempKey = new SecretKeySpec(decodedKey, SignatureAlgorithm.HS256.getJcaName());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read the '/token' file", e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid base64 encoding in '/token' file", e);
        }
        SECRET_KEY = tempKey;
    }


    //Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String generateToken(String username, String time) {
        Date now = new Date();

        // Check for infinite validity
        if ("-1".equals(time)) {
            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(now)
                    .signWith(SECRET_KEY)
                    .compact();
        }

        // Regular expiration
        int EXPIRATION_TIME = Integer.parseInt(time) * 60 * 1000;
        Date expiration = new Date(now.getTime() + EXPIRATION_TIME);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(SECRET_KEY)
                .compact();
    }


    public String extendTokenExpiration(String token,String time) {
        EXPIRATION_TIME = Integer.parseInt(time) * 60 * 1000;
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token);

        Claims claims = claimsJws.getBody();
        String username = claims.getSubject();
        Date now = new Date();
        Date newExpiration = new Date(now.getTime() + EXPIRATION_TIME);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(newExpiration)
                .signWith(SECRET_KEY)
                .compact();
    }

    public Map<String, Object> getUsernameFromToken(String token,String time) {
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token);

        Claims claims = claimsJws.getBody();
        String newToken = refreshToken(claims.getSubject(),time);
        Map<String, Object> m = new HashMap<>();
        m.put("userNmae",claims.getSubject());
        m.put("token",newToken);
        return m;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String refreshToken(String username,String time) {
        return generateToken(username,time);
    }


    /*public String invalidateToken(String token) {
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token);

        Claims claims = claimsJws.getBody();

        // Set the expiration time to the past
        Date now = new Date();
        claims.setExpiration(new Date(now.getTime() - 1000)); // Set to 1 second in the past

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(claims.getExpiration())
                .signWith(SECRET_KEY)
                .compact();
    }*/

}
