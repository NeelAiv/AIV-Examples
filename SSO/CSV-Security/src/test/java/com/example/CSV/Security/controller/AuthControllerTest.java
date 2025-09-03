package com.example.CSV.Security.controller;

import com.aivhub.security.HeaderSecurity;
import com.example.CSV.Security.security.CsvAuthenticationImpl;
import com.example.CSV.Security.security.JwtTokenUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthController Tests")
class AuthControllerTest {

    private AuthController authController;

    @Mock
    private JwtTokenUtil jwtTokenUtil;

    @Mock
    private CsvAuthenticationImpl csvAuthentication;

    private MockedConstruction<HeaderSecurity> mockedHeaderSecurity;

    @BeforeEach
    void setUp() throws Exception {
        Field instanceField = CsvAuthenticationImpl.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, csvAuthentication);

        mockedHeaderSecurity = mockConstruction(HeaderSecurity.class, (mock, context) -> {
            when(mock.getSecure(any(Map.class), anyString(), any(HttpServletRequest.class), any(), anyString()))
                    .thenReturn("http://localhost:9222/aiv/Default/sso_login?e=mocked-hex-payload");
        });

        authController = new AuthController();

        Field jwtTokenUtilField = AuthController.class.getDeclaredField("jwtTokenUtil");
        jwtTokenUtilField.setAccessible(true);
        jwtTokenUtilField.set(authController, jwtTokenUtil);
    }

    @AfterEach
    void tearDown() throws Exception {
        Field instanceField = CsvAuthenticationImpl.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);

        mockedHeaderSecurity.close();
    }

    @Test
    @DisplayName("handleLogin should succeed and redirect with correct credentials")
    void handleLogin_success() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/aiv");
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(9222);

        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("userName", "Admin");

        when(csvAuthentication.authenticate(any(Map.class))).thenReturn(userDetails);
        when(jwtTokenUtil.generateToken(anyString(), anyString())).thenReturn("dummy-token");

        String result = authController.handleLogin("Default::Admin", "password", request);

        assertEquals("redirect:http://localhost:9222/aiv/Default/sso_login?e=mocked-hex-payload", result);
    }

    @Test
    @DisplayName("handleLogin should fail and redirect to error page with incorrect credentials")
    void handleLogin_failure() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/aiv");

        when(csvAuthentication.authenticate(any(Map.class))).thenReturn(null);

        String result = authController.handleLogin("Default::Admin", "wrongpassword", request);

        assertEquals("redirect:/aiv/login?error=true", result);
    }

    @Test
    @DisplayName("decodePayload should succeed with valid hex")
    void decodePayload_success() {
        String hexPayload = "7b226b6579223a2276616c7565227d";

        ResponseEntity<String> response = authController.decodePayload(hexPayload);

        assertEquals(200, response.getStatusCodeValue());
        assertTrue(response.getBody().contains("\"key\" : \"value\""));
    }

    @Test
    @DisplayName("decodePayload should fail with invalid hex")
    void decodePayload_invalidHex() {
        String invalidHexPayload = "invalid-hex";

        ResponseEntity<String> response = authController.decodePayload(invalidHexPayload);

        assertEquals(400, response.getStatusCodeValue());
        assertTrue(response.getBody().contains("Invalid hex string provided"));
    }
}
