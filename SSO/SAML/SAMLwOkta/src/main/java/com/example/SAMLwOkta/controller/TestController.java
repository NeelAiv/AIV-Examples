package com.example.SAMLwOkta.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Controller
@RequestMapping("/")
public class TestController {

    private static final String SAML_LOGOUT_URL = "/logout";

    @PostMapping(path = "/{dept}/logout")
    public void logoutAIV(
            HttpServletRequest request,
            HttpServletResponse response,
            @PathVariable String dept,
            @RequestHeader(required = false, name = "traceid", defaultValue = "") String traceid) throws ServletException, IOException {

        request.getRequestDispatcher(SAML_LOGOUT_URL).forward(request, response);
    }

}
