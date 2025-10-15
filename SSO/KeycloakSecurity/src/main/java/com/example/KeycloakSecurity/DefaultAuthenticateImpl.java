package com.example.KeycloakSecurity;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.HeaderSecurity;
import com.aivhub.security.IAuthentication;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Service
public class DefaultAuthenticateImpl {

    public String authenticated(Map<String, Object> data, boolean isEmbed, DataSource dataSource, String traceid,String deptCode, HttpServletRequest req) {
        try {

            Class<?> implClass = Class.forName(GetBean.securityClass);
            IAuthentication i = (IAuthentication) implClass.getDeclaredConstructor().newInstance();
            i.setSource(dataSource,deptCode,traceid);

            Map<String, Object> loggedUser = null;
            if (i.isUserExists(data.get("userName").toString(),deptCode)) {
                loggedUser = i.authenticate(data);
                loggedUser.put("dc",loggedUser.get("department").toString());
                data.putAll(loggedUser);
            } else {
                loggedUser = new CommonUtility().checkUser(data,deptCode,traceid,i);
                data.put("userName", loggedUser.get("userName"));
                data.put("department", loggedUser.get("department"));
            }

            String resp;

            if (isEmbed) {
                data.put("isEmbed", isEmbed);
                resp = new HeaderSecurity().getSecure(data,deptCode, req, null, traceid);

            } else {
                data.put("isEmbed", isEmbed);
                resp = new HeaderSecurity().getSecure(data,deptCode, req, null, traceid);
            }


            return resp;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
                    traceid,deptCode, e);
            return null;
        }
    }


    public String authenticateAdmin(Map<String, Object> data, boolean isEmbed, DataSource dataSource, String traceid,String deptCode) {
        try {

            String resp = "";
            Map<String, Object> heads = new HashMap<>();


            heads.put("dc", deptCode);
            heads.put("traceid", traceid);



            KeycloakAuthImpl i = new KeycloakAuthImpl();
            Map<String,Object> u = i.authenticate(data);

            if (u==null) {
                return "Invalid Authentication";
            }
            data.putAll(u);

            return new HeaderSecurity().getSecure(data,deptCode, null, null, traceid);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
                    traceid,deptCode, e);
            return null;
        }
    }

//    public String authenticated(Map<String, Object> data, boolean isEmbed, DataSource dataSource, String traceid,String deptCode) {
//        try {
//
//            Class<?> implClass = Class.forName(GetBean.securityClass);
//            IAuthentication i = (IAuthentication) implClass.getDeclaredConstructor().newInstance();
//            i.setSource(dataSource,deptCode,traceid);
//
//            Map<String, Object> loggedUser = null;
//            if (i.isUserExists(data.get("userName").toString(),deptCode)) {
//                loggedUser = i.authenticate(data);
//                loggedUser.put("dc",loggedUser.get("department").toString());
//                data.putAll(loggedUser);
//            } else {
//                loggedUser = new CommonUtility().checkUser(data,deptCode,traceid,i);
//                data.put("userName", loggedUser.get("userName"));
//                data.put("department", loggedUser.get("department"));
//            }
//
//            String resp;
//
//            if (isEmbed) {
//                data.put("isEmbed", isEmbed);
//                resp = new HeaderSecurity().getSecure(data,deptCode,traceid);
//
//            } else {
//                data.put("isEmbed", isEmbed);
//                resp = new HeaderSecurity().getSecure(data,deptCode,traceid);
//            }
//
//
//            return resp;
//        } catch (Exception e) {
//            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
//                    traceid,deptCode, e);
//            return null;
//        }
//    }
//
//
//    public String authenticateAdmin(Map<String, Object> data, boolean isEmbed, DataSource dataSource, String traceid,String deptCode) {
//        try {
//
//            String resp = "";
//            Map<String, Object> heads = new HashMap<>();
//
//
//            heads.put("dc", deptCode);
//            heads.put("traceid", traceid);
//
//
//
//            KeycloakAuthImpl i = new KeycloakAuthImpl();
//            Map<String,Object> u = i.authenticate(data);
//
//            if (u==null) {
//                return "Invalid Authentication";
//            }
//            data.putAll(u);
//
//            return new HeaderSecurity().getSecure(data,deptCode,traceid);
//        } catch (Exception e) {
//            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
//                    traceid,deptCode, e);
//            return null;
//        }
//    }


}

