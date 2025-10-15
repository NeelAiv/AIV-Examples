package com.example.KeycloakSecurity;


import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.HeaderSecurity;
import com.aivhub.security.IAuthentication;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import javax.sql.DataSource;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebFilter("/*")
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class KeycloakFilter implements Filter {

    @Autowired
    OAuth2AuthorizedClientService clientService;

    @Lazy
    @Autowired
    @Qualifier("dataSource1")
    private DataSource dataSource1;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest sp = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String uri = sp.getRequestURI();

        String owner = sp.getHeader("owner") != null ?
                sp.getHeader("owner") : sp.getHeader("userName") != null ?
                sp.getHeader("userName") : null;

        String deptCode = sp.getHeader("dc") != null ?
                sp.getHeader("dc") : sp.getHeader("dc") != null ?
                sp.getHeader("dc") : null;

        String traceid = sp.getHeader("traceid") != null ?
                sp.getHeader("traceid") : sp.getHeader("traceid") != null ?
                sp.getHeader("traceid") : "SPRING AUTH";

        try {

            if (uri.contains("/v3/") || uri.endsWith("html") || uri.endsWith("css") || uri.endsWith("js") || uri.endsWith("png") || uri.endsWith("add_intl") || uri.endsWith("get_intl")
                    || (uri.endsWith("file_upload_servlet") && sp.getHeader("isLicenseUpload") != null
                    && "true".equalsIgnoreCase(sp.getHeader("isLicenseUpload"))) || uri.contains("licenserequest")  || uri.endsWith("papermill_upload")
                    || uri.endsWith("/external/update_user_role") || uri.endsWith("/api/user/validate")
                    || uri.endsWith("swf")   || uri.endsWith("woff") || uri.endsWith(".woff2") || uri.endsWith(".map") || uri.endsWith("jpg")  || uri.endsWith("svg")
                    || uri.endsWith(".json") || uri.endsWith("ttf") || uri.endsWith("TermsandConditions.pdf") || uri.endsWith("/dept_list") || uri.endsWith("/iconFile.json") || uri.endsWith("/license_info") || uri.endsWith("/endpoint/executed") || uri.endsWith("/aivverion")
                    || uri.endsWith("/aiv/logout")  || uri.contains("/allow/callback")) {
                chain.doFilter(request, response);
                return;
            }  else if (sp.getHeader("apitoken") != null) {
                chain.doFilter(sp, res);
                return;
            }

            Pattern pattern = Pattern.compile(
                    "^/aiv/(?!.*\\..*|logout|licenserequest|reportmap|run_report|load_document|myprofile|controlpanel|subreportrun|export_excel|download_word_file|download_file|load_jasper_htmlp|load_pentaho_htmlp|execute_adhoc_report|image_upload_servlet|file_upload_servlet|zip_files|GetMacId)[^/]+$"
            );
            Matcher matcher = pattern.matcher(uri);

            if (matcher.matches()) {
                System.out.println("came");
                Map<String, Object> heads = new HashMap<>();

                String contextPath = sp.getContextPath(); // e.g., /app
                String path = uri.substring(contextPath.length()); // e.g., /users/42

                String[] segments = path.split("/");
                String name = segments[1];

                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, this.getClass().getName(), "Cookie Ganied: " + sp.getSession().getId(), "Login", name, null);

                // heads.put("userName", "admin");
                heads.put("dc", name);
                heads.put("cookie", "JSESSIONID=" + sp.getSession().getId());
                heads.put("traceid", UUID.randomUUID().toString());
                heads.put("token", UUID.randomUUID().toString()); //
                heads.put("user-agent", sp.getHeader("user-agent") != null ? sp.getHeader("user-agent") :
                        sp.getHeader("User-Agent") != null ? sp.getHeader("User-Agent") : "");

                Map<String, Object> user = new CommonUtility().getUserInfo(clientService,name,traceid);
                heads.putAll(user);

                //Genearte new token for internal session and authentication
                String utoken = new JwtTokenUtil().generateToken(user.get("userName").toString(),new HeaderSecurity().getSessionTime());
                heads.put("token", utoken);

                Map<String, Object> additionalHeaders = new HashMap<>();
                additionalHeaders.put("token", utoken); //Just add if you want else fine
                heads.put("additionalHeaders", additionalHeaders);

                heads.put("owner", user.get("userName"));

                String responseData = null;

//                String frontendgatewayApp = GetBean.frontendgatewayApp.replaceAll("\\{deptCode\\}", name.equalsIgnoreCase("sso") ? "sso" : name);
//                res.addHeader("auth-token", "AIV");
//                Map<String,Object> extraData = new HashMap<>();
//                extraData.put("isEmbed", "false");

                    responseData = new DefaultAuthenticateImpl().authenticated(heads, false,dataSource1, heads.get("traceid").toString(),name, sp); //uncomment for new
                System.out.println("Response data in filter:" + responseData);
//                System.out.println("Frontend gateway: " + frontendgatewayApp);
//                    responseData = new DefaultAuthenticateImpl().authenticated(heads, false,dataSource1, heads.get("traceid").toString(),name);
                    res.sendRedirect(responseData);
                    return;
            } else if (uri.contains("/embed/external/") && sp.getParameter("e") == null) {
                Map<String, Object> heads = new HashMap<>();

                String contextPath = sp.getContextPath(); // e.g., /app
                String path = uri.substring(contextPath.length()); // e.g., /users/42

                String[] segments = path.split("/");
                String name = segments[1];

                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, this.getClass().getName(), "Cookie Ganied: " + sp.getSession().getId(), "Login", name, null);
                res.addHeader("token", "AIV");

                StringBuffer requestURL = sp.getRequestURL();
                String queryString = sp.getQueryString();

                String  redirectUri = "";
                if (queryString != null) {
                    redirectUri = requestURL.append('?').append(queryString).toString();
                }
                // heads.put("userName", "admin");
                heads.put("dc", name);
                heads.put("cookie", "JSESSIONID=" + sp.getSession().getId());
                heads.put("traceid", UUID.randomUUID().toString());
                heads.put("token", UUID.randomUUID().toString());
                heads.put("user-agent", sp.getHeader("user-agent") != null ? sp.getHeader("user-agent") :
                        sp.getHeader("User-Agent") != null ? sp.getHeader("User-Agent") : "");
                String responseData = null;
                Map<String, Object> data = new HashMap<>();
                String splits[] = uri.toString().split("/");

                for (String n : splits) {
                    if (n.contains("a_d__") || n.contains("a_u__") || n.contains("a_p__")) {
                        for (String n1 : n.split("&")) {
                            if (n1.contains("a_d__")) {
                                deptCode = n1.split("a_d__")[1];
                                data.put("deptCode", deptCode);
                            } else if (n1.contains("a_u__")) {
                                data.put("userName", n1.split("a_u__")[1]);
                            } else if (n1.contains("a_p__")) {
                                String p[] = n1.split("a_p__");
                                data.put("password", p.length > 1 ? p[1] : null);
                            } else if (n1.contains("a_t__")) {
                                String p[] = n1.split("a_t__");
                                data.put("token", p.length > 1 ? p[1] : null);
                            }
                        }
                    }
                }

                data.put("keyinfo", uri.toString().split("external/")[1].split("/")[0]);
                data.put("isEmbed","true");

                responseData = new DefaultAuthenticateImpl().authenticated(heads, true,dataSource1, heads.get("traceid").toString(),name, sp);//uncomment for new
//                responseData = new DefaultAuthenticateImpl().authenticated(heads, true,dataSource1, heads.get("traceid").toString(),name);
                res.sendRedirect(sp.getScheme() + "://" + sp.getServerName() + ":" + sp.getServerPort()
                        +uri+"?e="+responseData);
               // res.sendRedirect(redirectUri + "?e=" + responseData);
                return;
            } else if (uri.contains("/embed/internal/") && sp.getQueryString() == null) {

                chain.doFilter(sp, res);
                return;


            } else if (uri.endsWith("logout")) {
                chain.doFilter(sp, res);
                return;
            } else if (CommonUtility.isAuthneticated(traceid, deptCode)) {
                if (uri.contains("/v5") || uri.contains("file_upload_servlet")
                        || uri.contains("download_file") || uri.contains("download_word_file")
                        || uri.contains("export_excel") || uri.contains("image_upload_servlet")
                        || uri.contains("zip_files") || uri.contains("load_document") || uri.contains("subreportrun")
                        || uri.contains("execute_adhoc_report")) {

                    if (sp.getHeader("stoken") != null || sp.getParameter("stoken") != null) {
                        String stoken = sp.getHeader("stoken") != null ? sp.getHeader("stoken") :
                                sp.getParameter("stoken") != null ? sp.getParameter("stoken") : null;

                        DataSource dataSource = GetBean.context != null ? (DataSource) GetBean.context.getBean("dataSource1") : null;
                        Map<String, Object> arr = new HashMap<String, Object>();

                        if (stoken != null) {
                            arr = new HeaderSecurity().getSTokenInfo(stoken,"AUTH",traceid);
                        }

                        if (sp.getHeader("token") != null || sp.getParameter("token") != null) {
                            String oldtoken = sp.getHeader("token") != null ? sp.getHeader("token") : sp.getParameter("token");

                            arr.put("token",oldtoken);

                            String traceid1 = sp.getParameter("traceid");
                            if (traceid1 != null && !traceid1.equalsIgnoreCase("")) {
                                arr.put("traceid",traceid1);
                            }

                            Class<?> implClass = Class.forName(GetBean.securityClass);
                            IAuthentication i = (IAuthentication) implClass.getDeclaredConstructor().newInstance();
                            i.setSource(dataSource, arr.get("dc").toString(), traceid);

                            boolean b = i.isAuthorize(arr);


                            if (b) {

                                res.addHeader("token", new JwtTokenUtil().extendTokenExpiration(oldtoken, new HeaderSecurity().getSessionTime()));

                            } else {
                                res.getWriter().print("Session Expired");
                                return;
                            }

                            //new JwtTokenUtil().invalidateToken(oldtoken);

                            chain.doFilter(sp, res);
                            return;
                        } else if (sp.getHeader("apitoken") != null) {
                            chain.doFilter(sp, res);
                            return;
                        }

                    }

                } else {
                    res.addHeader("token", "AIV");
                    chain.doFilter(sp,res);
                    return;
                }
            }  else {
                res.addHeader("token", "AIV");
                chain.doFilter(sp,res);
                return;
            }


        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), "Login", "Login", e);
            res.getWriter().print("UnAuthorized access.");
            return;
        }
    }

}

