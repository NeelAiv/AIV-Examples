package com.security.security;

import com.aivhub.logs.AuditLoggerUtil;
import com.security.services.CommonConfig;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@WebFilter("/*")
public class AuthenticationFilter implements Filter {


    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        try {
            String uri = req.getRequestURI();

            Enumeration<String> params = req.getParameterNames();

            while (params.hasMoreElements()) {
                String name = params.nextElement();
                List<String> a = Arrays.asList(req.getParameterValues(name));
                boolean fg = a.stream().anyMatch(j -> {
                    return j.contains("\r") || j.contains("\n");
                });

                if (fg) {
                    throw new IOException();
                }

            }


            String ssotoken =  req.getAttribute("sso") == null ? null : req.getAttribute("sso").toString();

            if (uri.endsWith("/aiv/") || uri.contains("/eAuth") || uri.endsWith("/authenticate") || uri.endsWith("html") || uri.endsWith("css") || uri.endsWith("js") || uri.endsWith("png") || uri.endsWith("add_intl") || uri.endsWith("get_intl")
                    || (uri.endsWith("file_upload_servlet") && req.getHeader("isLicenseUpload") != null
                    && "true".equalsIgnoreCase(req.getHeader("isLicenseUpload"))) || uri.contains("licenserequest")  || uri.endsWith("papermill_upload")
                    || uri.endsWith("/external/update_user_role") || uri.endsWith("/api/user/validate")
                    || uri.endsWith("swf") ||  (ssotoken == null && uri.contains("embed") )  || uri.endsWith("woff") || uri.endsWith(".woff2") || uri.endsWith(".map") || uri.endsWith("jpg")  || uri.endsWith("svg")
                    || uri.endsWith("json") || uri.endsWith("ttf") || uri.endsWith("TermsandConditions.pdf") || uri.endsWith("/dept_list") || uri.endsWith("/iconFile.json") || uri.endsWith("/license_info") || uri.endsWith("/endpoint/executed") || uri.endsWith("/aivverion")) {
                chain.doFilter(request, response);
                return;
            } else {
                List<String> addInfo = new ArrayList<String>();
                addInfo.add(req.getHeader("User-Agent"));

                /*String token = req.getHeader("token") != null ? req.getHeader("token").toString() : null;
                if (token != null  && CommonConfig.isAuthneticated(token,null,null)) {
                    String refreshedTokentoken = CommonConfig.refreshToken(token);

                    res.setHeader("token", token);
                } else {
                    res.getWriter().print("Session Expired");
                    return;
                   *//* if (Bc.aiv_departments.containsKey(uName)) {
                        Bc.aiv_departments.remove(uName);
                    }*//*
                }*/

            }

            chain.doFilter(req,res);
            return;
       } catch (Exception e) {
           AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(),"AUTH","AUTH", e);
           res.getWriter().print("Session Expired");
           return;
       }





    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

}
