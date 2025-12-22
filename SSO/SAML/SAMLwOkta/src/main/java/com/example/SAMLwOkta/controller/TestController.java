package com.example.AIVsaml.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

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
