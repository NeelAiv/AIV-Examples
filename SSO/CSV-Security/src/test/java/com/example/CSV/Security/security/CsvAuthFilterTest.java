package com.example.CSV.Security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CsvAuthFilterTest {

    private final CsvAuthFilter filter = new CsvAuthFilter();

    @Test
    void doFilter_excludedPath() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/aiv/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_aivEntryPoint_redirectsToLogin() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/aiv/Default");
        request.setContextPath("/aiv");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertEquals("/aiv/login", response.getRedirectedUrl());
    }

    @Test
    void doFilter_ssoLogin_passesThrough() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/aiv/Default/sso_login");
        request.setParameter("e", "somepayload");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
