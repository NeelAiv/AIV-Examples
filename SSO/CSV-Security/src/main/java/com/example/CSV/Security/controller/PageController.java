package com.example.CSV.Security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class PageController {

    @GetMapping({"/", "/login"})
    public String showLoginPage() {
        return "login.html";
    }

    @GetMapping("/success")
    @ResponseBody
    public String showSuccessPage() {
        return "<h1>Backend Redirect Successful!</h1><p>You have been successfully authenticated.</p>";
    }

}