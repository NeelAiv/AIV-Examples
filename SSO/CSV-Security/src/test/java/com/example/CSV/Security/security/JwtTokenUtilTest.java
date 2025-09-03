package com.example.CSV.Security.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenUtilTest {

    private final JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();

    @Test
    void generateAndValidateToken() {
        String token = jwtTokenUtil.generateToken("testuser", "1");
        assertTrue(jwtTokenUtil.validateToken(token));
    }

    @Test
    void validateToken_invalid() {
        assertFalse(jwtTokenUtil.validateToken("invalid-token"));
    }

    @Test
    void extendTokenExpiration() throws Exception {
        String oldToken = jwtTokenUtil.generateToken("testuser", "1");
        String extendedToken = jwtTokenUtil.extendTokenExpiration(oldToken, 3600);

        assertNotEquals(oldToken, extendedToken);
        assertTrue(jwtTokenUtil.validateToken(extendedToken));
    }

    @Test
    void getUsernameFromToken() {
        String token = jwtTokenUtil.generateToken("testuser", "1");
        assertEquals("testuser", jwtTokenUtil.getUsernameFromToken(token));
    }

    @Test
    void isTokenExpired() throws InterruptedException {
        String token = jwtTokenUtil.generateToken("testuser", "0");
        Thread.sleep(1000);
        assertTrue(jwtTokenUtil.isTokenExpired(token));
    }
}