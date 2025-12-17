package com.security.services;


import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.EC;
import com.aivhub.security.HeaderSecurity;
import com.security.security.PaaswordCryptography;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;

import java.util.*;



@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class FirstFilter implements Filter {

    Properties p = null;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;

            String userAgent = req.getHeader("user-agent");

            String owner = req.getHeader("owner") != null ?
                    req.getHeader("owner") : req.getHeader("userName") != null ?
                    req.getHeader("userName") : null;

            String traceid = req.getHeader("traceid") != null ?
                    req.getHeader("traceid") : req.getHeader("traceid") != null ?
                    req.getHeader("traceid") : "SPRING AUTH";

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


                //String ssotoken =  req.getAttribute("sso") == null ? null : req.getAttribute("sso").toString();

                if (uri.contains("/v3/") || uri.endsWith("html") || uri.endsWith("css") || uri.endsWith("js") || uri.endsWith("png") || uri.endsWith("add_intl") || uri.endsWith("get_intl")
                        || (uri.endsWith("file_upload_servlet") && req.getHeader("isLicenseUpload") != null
                        && "true".equalsIgnoreCase(req.getHeader("isLicenseUpload"))) || uri.contains("licenserequest")  || uri.endsWith("papermill_upload")
                        || uri.endsWith("/external/update_user_role") || uri.endsWith("/api/user/validate")
                        || uri.endsWith("swf")   || uri.endsWith("woff") || uri.endsWith(".woff2") || uri.endsWith(".map") || uri.endsWith("jpg")  || uri.endsWith("svg")
                        || uri.endsWith(".json") || uri.endsWith("ttf") || uri.endsWith("TermsandConditions.pdf") || uri.endsWith("/dept_list") || uri.endsWith("/iconFile.json") || uri.endsWith("/license_info") || uri.endsWith("/endpoint/executed") || uri.endsWith("/aivverion")
                        || uri.endsWith("/aiv/logout")  || uri.contains("/allow/callback")) {
                    chain.doFilter(request, response);
                    return;
                }

                    List<String> addInfo = new ArrayList<String>();
                    addInfo.add(req.getHeader("User-Agent"));

                    if (uri.endsWith("/aiv/")) {
                        String aivlite = new HeaderSecurity().getaivLite();
                        if (aivlite != null && !aivlite.isBlank() && aivlite.equalsIgnoreCase("v")
                                || aivlite.equalsIgnoreCase("vr") || aivlite.equalsIgnoreCase("r")) {
                            String userName="Admin", deptCode="Default";
                            String responseData = null;
                            Map<String, Object> user = new HashMap<>();
                            if(userName !=null){
                                SimpleAuthImpl i = new SimpleAuthImpl();

                                Map<String, Object> d = new HashMap<>();

                                //user.put("password",pass);
                                //user.put("salt","Activeintelligence");
                                user.put("archiveMode", req.getHeader("archiveMode") != null ? req.getHeader("archiveMode") : false);
                                user.put("owner",userName);
                                user.put("isDatasource", true);
                                user.put("isAdmin", true);

                                //token by which user will get authenticated.
                                String utoken = new JwtTokenUtil().generateToken(userName,"-1");

                                Map<String, Object> additionalHeaders = new HashMap<>();

                                //main which are required to send
                                user.put("userName",userName);
                                user.put("deptCode",deptCode);
                                user.put("dc",deptCode);
                                user.put("traceid", UUID.randomUUID().toString());
                                user.put("token", utoken);
                               // user.put("token", UUID.randomUUID().toString());

                             //   user.put("additionalHeaders", additionalHeaders);

                            }

                            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.INFO, FirstFilter.class, "User :"+userName
                                    +" logged in with traceid: "+ traceid, traceid, deptCode, null);

                            responseData = new DefaultAuthenticateImpl().directauthenticated(user,req, deptCode);

                            if (responseData == null || responseData.equalsIgnoreCase("Invalid Authentication")) {
                                return;
                            } else {
                                res.setContentType("application/json");
                                res.setCharacterEncoding("UTF-8");
                                res.getWriter().print("[]");
                                res.setStatus(302);
                                if (req.getServerPort() == 4200) {
                                    res.sendRedirect(req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort()
                                            + "/"+deptCode+"/sso_login?e="+responseData);
                                } else {
                                    res.sendRedirect(responseData);
                                }

                            }
                        }

                    }

                    if (req.getMethod().equalsIgnoreCase("POST") && uri.endsWith("/authenticate")) {
                        String str = IOUtils.toString(request.getInputStream(),StandardCharsets.UTF_8);
                        String userName = null,pass = null,deptCode = null;
                        traceid = UUID.randomUUID().toString();

                        if(str !=null && str.length()>0)
                        {
                            JSONObject jsonObj = new JSONObject(str);
                            if(jsonObj!=null){
                                userName = jsonObj.getString("userName");
                                String[] _su = userName.contains("::") ? userName.split("::") : userName.split("/");
                                pass = jsonObj.getString("password");
                                System.out.println(pass);
                                deptCode = jsonObj.getString("deptCode");
                                if(jsonObj.has("embed") && jsonObj.get("embed").equals(true)) {
                                    try {
                                        pass = new PaaswordCryptography().decryptEmbedPass(pass);
                                    } catch (Exception e) {
                                        // TODO Auto-generated catch block
                                        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR,
                                                FirstFilter.class, e.getMessage(),"AUTH","AUTH", e);
                                    }
                                }
                                if(_su.length>1) {
                                    deptCode=_su[0];
                                    userName=_su[1];
                                }
                            }
                        }
                        String responseData = null;
                        Map<String, Object> user = new HashMap<>();
                        if(userName !=null){
                            SimpleAuthImpl i = new SimpleAuthImpl();

                            Map<String, Object> d = new HashMap<>();

                            user.put("password",pass);
                            user.put("salt","Activeintelligence");
                            //optional
                            user.put("archiveMode", req.getHeader("archiveMode") != null ? req.getHeader("archiveMode") : false);
                            user.put("owner",userName);

                            //optional
                            user.put("isDatasource", true);

                            //optional
                            user.put("isAdmin", true);

                            //token by which user will get authenticated.
                            String utoken = new JwtTokenUtil().generateToken(userName,new HeaderSecurity().getSessionTime());

                            //Map<String, Object> additionalHeaders = new HashMap<>();

                            //main which are required to send
                            user.put("userName",userName);
                            user.put("deptCode",deptCode);
                            //user.put("traceid", UUID.randomUUID().toString());
                           // user.put("auth-token", utoken);
                            user.put("token", utoken);

                           // user.put("additionalHeaders", additionalHeaders);

                        }

                        AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.INFO, FirstFilter.class, "User :"+userName
                                +" logged in with traceid: "+ traceid, traceid, deptCode, null);

                        responseData = new DefaultAuthenticateImpl().authenticated(user,req,null, deptCode);

                        if (responseData == null || responseData.equalsIgnoreCase("Invalid Authentication")) {
                            return;
                        } else {
                            res.setContentType("application/json");
                            res.setCharacterEncoding("UTF-8");
                            res.getWriter().print("[]");
                            res.setStatus(302);
                            if (req.getServerPort() == 4200) {
                                res.sendRedirect(req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort()
                                         + "/"+deptCode+"/sso_login?e="+responseData);
                            } else {
                              //  res.sendRedirect(req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort()
                               //         + req.getContextPath() + "/"+deptCode+"/sso_login?e="+responseData);
                                res.sendRedirect(responseData);
                            }

                        }


                    } else if (req.getMethod().equalsIgnoreCase("POST") && uri.endsWith("/auths")) {
                        String str = IOUtils.toString(request.getInputStream(),StandardCharsets.UTF_8);
                        String userName = null,pass = null,deptCode = null;
                        traceid = UUID.randomUUID().toString();

                        if(str !=null && str.length()>0)
                        {
                            JSONObject jsonObj = new JSONObject(str);
                            if(jsonObj!=null){
                                userName = jsonObj.getString("userName");
                                String[] _su = userName.contains("::") ? userName.split("::") : userName.split("/");
                                pass = jsonObj.getString("password");
                                deptCode = jsonObj.getString("deptCode");
                                if(jsonObj.has("embed") && jsonObj.get("embed").equals(true)) {
                                    try {
                                        pass = new PaaswordCryptography().decryptEmbedPass(pass);
                                    } catch (Exception e) {
                                        // TODO Auto-generated catch block
                                        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR,
                                                FirstFilter.class, e.getMessage(),"AUTH","AUTH", e);
                                    }
                                }
                                if(_su.length>1) {
                                    deptCode=_su[0];
                                    userName=_su[1];
                                }
                            }
                        }
                        String responseData = null;
                        Map<String, Object> user = new HashMap<>();
                        if(userName !=null){
                            SimpleAuthImpl i = new SimpleAuthImpl();

                            Map<String, Object> d = new HashMap<>();
                            user.put("userName",userName);
                            user.put("password",pass);
                            user.put("deptCode",deptCode);
                            user.put("salt","Activeintelligence");

                            user.put("archiveMode", req.getHeader("archiveMode") != null ? req.getHeader("archiveMode") : false);
                            user.put("owner",userName);
                            user.put("isDatasource", true);
                            user.put("isAdmin", true);
                        }

                        AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.INFO, FirstFilter.class, "User :"+userName
                                +" logged in with traceid: "+ traceid, traceid, deptCode, null);

                        responseData = new DefaultAuthenticateImpl().auths(user, deptCode);

                        res.setContentType("application/json");
                        res.setCharacterEncoding("UTF-8");
                        res.getWriter().print(responseData);
                        return;
                    }
                    else if (uri.contains("/embed/external/") && req.getQueryString() == null) {

                        String responseData = null;

                        String splits[] = uri.toString().split("/");

                        Map<String, Object> passData = new HashMap<>();
                        String deptCode = "";
                        for (String n : splits) {
                            if (n.contains("a_d__") || n.contains("a_u__") || n.contains("a_p__")) {
                                for (String n1 : n.split("&")) {
                                    if (n1.contains("a_d__")) {
                                        deptCode = n1.split("a_d__")[1];
                                        passData.put("deptCode", deptCode);
                                    } else if (n1.contains("a_u__")) {
                                        passData.put("userName", n1.split("a_u__")[1]);
                                    } else if (n1.contains("a_p__")) {
                                        String p[] = n1.split("a_p__");
                                        passData.put("password", p.length > 1 ? p[1] : null);
                                    } else if (n1.contains("a_t__")) {
                                        String p[] = n1.split("a_t__");
                                        passData.put("ctoken", p.length > 1 ? p[1] : null);
                                    }
                                }
                            }
                        }

                        passData.put("keyInfo", uri.toString().split("external/")[1].split("/")[0]);


                        passData.put("isEmbed", true);


                        //token by which user will get authenticated.
                        String utoken = new JwtTokenUtil().generateToken(passData.get("userName").toString(),new HeaderSecurity().getSessionTime());

                        Map<String, Object> additionalHeaders = new HashMap<>();

                        //main which are required to send
                        passData.put("dc",deptCode);
                        passData.put("traceid", UUID.randomUUID().toString());
                        passData.put("token", utoken);
                        //passData.put("token", UUID.randomUUID().toString());

                        passData.put("additionalHeaders", additionalHeaders);

                        responseData = new DefaultAuthenticateImpl().authenticated(passData,req,uri, deptCode);

                        if (responseData == null || responseData.equalsIgnoreCase("Invalid Authentication")) {
                            return;
                        } else {
                            res.setContentType("application/json");
                            res.setCharacterEncoding("UTF-8");
                           // res.addHeader("token", passData.get("token").toString());
                            //res.sendRedirect(req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort()
                            //        +uri+"?e="+responseData);
                            res.sendRedirect(responseData);
                        }




                    } else if (uri.contains("/embed/internal/") && req.getQueryString() == null) {

                        chain.doFilter(req, res);
                        return;


                    } else if (uri.contains("/re_schedule_session")) {
                        String oldtoken = req.getHeader("token") != null ? req.getHeader("token") : req.getParameter("token");

                        try {
                            res.addHeader("token", new JwtTokenUtil().extendTokenExpiration(oldtoken, new HeaderSecurity().getSessionTime()));
                        } catch (Exception e) {
                            res.getWriter().print("Session Expired");
                            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR,
                                    FirstFilter.class, "Something went wrong",traceid,"AUTH", e);
                            return;
                        }
                        chain.doFilter(req, res);
                        return;
                    } else if (uri.contains("/v5/api/logout")) {

                        res.getWriter().print(true);
                        return;
                    } else if (uri.contains("/v5") || uri.contains("file_upload_servlet")
                            || uri.contains("download_file") || uri.contains("download_word_file")
                            || uri.contains("export_excel") || uri.contains("image_upload_servlet")
                            || uri.contains("zip_files") || uri.contains("load_document") || uri.contains("subreportrun")
                            || uri.contains("execute_adhoc_report")) {



                        if (req.getHeader("token") != null || req.getParameter("token") != null) {
                            String oldtoken = req.getHeader("token") != null ? req.getHeader("token") : req.getParameter("token");
                            //res.addHeader("auth-token", new JwtTokenUtil().extendTokenExpiration(oldtoken, new HeaderSecurity().getSessionTime()));
                            try {
                                res.addHeader("token", new JwtTokenUtil().extendTokenExpiration(oldtoken, new HeaderSecurity().getSessionTime()));
                            } catch (Exception e) {
                                res.getWriter().print("Session Expired");
                                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR,
                                        FirstFilter.class, "Something went wrong",traceid,"AUTH", e);
                                return;
                            }
                            //new JwtTokenUtil().invalidateToken(oldtoken);

                            chain.doFilter(req, res);
                            return;
                        } else if (req.getHeader("apitoken") != null) {
                            chain.doFilter(req, res);
                            return;
                        } else if (uri.contains("file_upload_servlet")
                                || uri.contains("download_file") || uri.contains("download_word_file")
                                || uri.contains("export_excel") || uri.contains("image_upload_servlet")
                                || uri.contains("zip_files") || uri.contains("load_document") || uri.contains("subreportrun")
                                || uri.contains("execute_adhoc_report") || uri.contains("run") || uri.contains("run_report")) {
                            chain.doFilter(req, res);
                            return;
                        }


                    } else if (uri.contains("/eAuth")) {
                        try {

                            String splits[] = uri.toString().split("/");
                            Map<String, Object> passData = new HashMap<>();
                            for (String n : splits) {
                                if (n.contains("a_d__") || n.contains("a_u__") || n.contains("a_p__")) {
                                    for (String n1 : n.split("&")) {
                                        if (n1.contains("a_d__")) {
                                            passData.put("name", n1.split("a_d__")[1]);
                                        } else if (n1.contains("a_u__")) {
                                            passData.put("userName", n1.split("a_u__")[1]);
                                        } else if (n1.contains("a_p__")) {
                                            passData.put("password", n1.split("a_p__")[1]);
                                        }
                                    }
                                }
                            }

                            passData.put("keyinfo", uri.toString().split("external/")[1].split("/")[0]);




                            String responseData = null;
                            ServletRequest req1 = request;
                            String str,deptCode = null;
                            JSONObject jsonObj = null;
                            String uname = null; //UserBean ub = null;
                            Map<String, Object> sb = null;

                            Map<String,Object> obj= null;
                            String rm_pm = null;
                            Map<String, Object> user = new HashMap<>();

                            str = IOUtils.toString(req1.getInputStream());

                            if(str !=null && str.length()>0)
                            {
                                jsonObj = new JSONObject(str);
                                if(jsonObj!=null){

                                    uname = jsonObj.has("userName") ? jsonObj.getString("userName") : null;
                                    deptCode = jsonObj.getString("deptCode");
                                    if(StringUtils.isBlank(uname)) {
                                        EC ac = new EC(deptCode,"Embed Login");
                                        String tk = ac.decryptEmbedUrlKey(jsonObj.getString("keyInfo"));
                                        uname = tk.split("::")[0];
                                    }

                                    if(uname !=null){

                                        String pwd = StringUtils.isNotBlank(jsonObj.getString("password")) ? jsonObj.getString("password") : jsonObj.getString("token");
                                        try {
                                            pwd = new CommonConfig().md5String(new HeaderSecurity().getSlatKey() + pwd,deptCode,traceid);
                                        } catch (Exception e) {
                                            // TODO Auto-generated catch block
                                            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR,
                                                    FirstFilter.class, e.getMessage(),traceid,deptCode, e);
                                        }


                                        Map<String, Object> d = new HashMap<>();
                                        d.put("userName",uname);
                                        d.put("password",pwd);
                                        d.put("deptCode",deptCode);
                                        d.put("addInfo",addInfo);
                                        d.put("keyInfo",jsonObj.getString("keyInfo"));
                                        d.put("isEmbed",true);
                                        responseData = new DefaultAuthenticateImpl().authenticated(d,req,uri, deptCode);
                                    }

                                    if (responseData == null) {
                                        res.getWriter().print("Wrong Credentials");
                                        res.sendRedirect(req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort()
                                                + req.getContextPath() + "/");
                                    } else {
                                        res.addHeader("token", "AIV");

                                        res.setContentType("application/json");
                                        res.setCharacterEncoding("UTF-8");
                                        res.sendRedirect(responseData);
                                    }
                                }



                            }


                        }catch (Exception e) {
                            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR,
                                    FirstFilter.class, "Error while reading user credentials",traceid,"AUTH", e);
                            return;
                        }

                    }  else if (uri.contains("/v5/api/logout")) {
                        res.getWriter().print(true);
                        Map<String, Object> arr = new HashMap<String, Object>();

                        String stoken = req.getHeader("stoken") != null ? req.getHeader("stoken") :
                                req.getParameter("stoken") != null ? req.getParameter("stoken") : null;
                        if (stoken != null) {
                            arr = new HeaderSecurity().getSTokenInfo(stoken,"AUTH",traceid);
                        }
                        JSONObject js = null;
                            js = new JSONObject(new HeaderSecurity().fromHexString(arr.get("additional_token").toString()));
                        //new JwtTokenUtil().invalidateToken(js.getString("token"));
                        return;
                    } else {




                        if (req.getHeader("token") != null) {
                            String oldtoken = req.getHeader("token");


                            if (oldtoken != null && !oldtoken.equalsIgnoreCase("")){

                                try {
                                    res.addHeader("token", new JwtTokenUtil().extendTokenExpiration(oldtoken, new HeaderSecurity().getSessionTime()));
                                } catch (Exception e) {
                                    res.getWriter().print("Session Expired");
                                    AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR,
                                            FirstFilter.class, "Something went wrong",traceid,"AUTH", e);
                                    return;
                                }

                            }

                            String uName = req.getHeader("userName") != null ? req.getHeader("userName")
                                    : req.getParameter("userName") != null ? req.getParameter("userName")
                                    : "null";
                            String dc= req.getHeader("dc") != null ? req.getHeader("dc")
                                    : req.getParameter("dc") != null ? req.getParameter("dc")
                                    : "null";
                            // res.setHeader("auth-token", "AIV");
                            chain.doFilter(req, res);
                            return;
                        } else if (req.getHeader("apitoken") != null) {
                            chain.doFilter(req, res);
                            return;
                        } else {
                            chain.doFilter(req, res);
                            return;
                        }


                    }




        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR,
                    FirstFilter.class, e.getMessage(), "AUTH", "", e);
        }
    }

    public boolean isAUth(HttpServletRequest req, HttpServletResponse res) {

        return true;
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    private String findMacId() {
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            boolean flag = true;
            StringBuilder sb = null;
            while (flag && networkInterfaces.hasMoreElements()) {
                NetworkInterface network = networkInterfaces.nextElement();
                String name = network.getName();
                if (name.contains("eth") || name.contains("ens")) {

                    Enumeration<InetAddress> a = network.getInetAddresses();
                    for (; a.hasMoreElements();) {

                        InetAddress addr = a.nextElement();
                        String hostAdd = addr.getHostAddress();
                        if (hostAdd.contains(name) || hostAdd.contains(":")) {

                        } else {
                            sb = new StringBuilder();
                            sb.append("IP:" + hostAdd + ",ID:");
                            byte[] bmac = network.getHardwareAddress();
                            if (bmac != null) {
                                for (int i = 0; i < bmac.length; i++) {
                                    sb.append(String.format("%02X%s", bmac[i], (i < bmac.length - 1) ? "-" : ""));
                                }
                            }
                            flag = false;
                            break;
                        }
                    }

                }
            }
            if (sb != null && sb.toString().length() > 0)
                return sb.toString();
            else {
                StringBuffer s = new StringBuffer();
                InetAddress ip = InetAddress.getLocalHost();
                s.append("IP:" + ip.getHostAddress() + ",ID:");
                byte[] mac = null;
                if (ip != null && NetworkInterface.getByInetAddress(ip) != null) {
                    mac = NetworkInterface.getByInetAddress(ip).getHardwareAddress();
                }
                if (mac != null) {
                    for (int i = 0; i < mac.length; i++)
                        s.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                } else {
                    s.append("00-00-00-00-00-00");
                }
                return s.toString();


            }

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR, FirstFilter.class,
                    "Error while getting machine key","AUTH","AUTH", e);
            return "Error";
        }
    }

}
