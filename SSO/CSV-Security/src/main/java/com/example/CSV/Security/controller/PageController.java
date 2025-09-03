package com.example.CSV.Security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class PageController {

    @GetMapping({"/", "/login"})
    public String showLoginPage() {
        return "login.html";
    }

    @PostMapping("/{deptCode}/logout")
    public String handleAivLogout() {
        System.out.println("Intercepted AIV POST to /logout. Redirecting to custom login page.");
        return "redirect:/login?logout=true";
    }

    @GetMapping("/success")
    @ResponseBody
    public String showSuccessPage() {
        return "<h1>Backend Redirect Successful!</h1><p>You have been successfully authenticated.</p>";
    }

}