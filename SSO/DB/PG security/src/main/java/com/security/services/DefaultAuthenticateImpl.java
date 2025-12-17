package com.security.services;

import com.aivhub.logs.AuditLoggerUtil;

import com.aivhub.security.EmbedJwtToken;
import com.aivhub.security.HeaderSecurity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class DefaultAuthenticateImpl {

    public String authenticated(Map<String, Object> data, HttpServletRequest req,String uri, String deptCode) {
        String traceid = UUID.randomUUID().toString();
        try {


            if (data.containsKey("isEmbed") && Boolean.parseBoolean(data.get("isEmbed").toString())) {
                EmbedJwtToken ejwt = new EmbedJwtToken();
                boolean valid = ejwt.validateToken(data.get("ctoken").toString());

                if (!valid) {
                    return "Invalid Authentication";
                } else {
                    AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, data.toString(),
                            traceid,deptCode, null);
                    data.putAll(new HeaderSecurity().getEmbedDetails(data.get("userName").toString(),deptCode,data.get("keyInfo").toString(),traceid));
                    return new HeaderSecurity().getSecure(data,deptCode,req,uri,traceid);
                }

            } else {
                SimpleAuthImpl i = new SimpleAuthImpl();
                Map<String,Object> u = i.authenticate(data);

                if (u==null) {
                    return "Invalid Authentication";
                }
                data.putAll(u);
                return new HeaderSecurity().getSecure(data,deptCode,req,null,traceid);
            }


        } catch (Exception e) {
             AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
                     traceid,deptCode, e);
            return null;
        }
    }

    public String directauthenticated(Map<String, Object> data,HttpServletRequest req,String deptCode) {
        String traceid = UUID.randomUUID().toString();
        try {


            if (data.containsKey("isEmbed") && Boolean.parseBoolean(data.get("isEmbed").toString())) {
                EmbedJwtToken ejwt = new EmbedJwtToken();
                boolean valid = ejwt.validateToken(data.get("token").toString());

                if (!valid) {
                    return "Invalid Authentication";
                } else {
                    AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, data.toString(),
                            traceid,deptCode, null);
                    data.putAll(new HeaderSecurity().getEmbedDetails(data.get("userName").toString(),deptCode,data.get("keyInfo").toString(),traceid));
                }

            } else {
                SimpleAuthImpl i = new SimpleAuthImpl();
                Map<String,Object> u = data;

                if (u==null) {
                    return "Invalid Authentication";
                }
                data.putAll(u);
            }

            return new HeaderSecurity().getSecure(data,deptCode,req,null,traceid);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
                    traceid,deptCode, e);
            return null;
        }
    }

    public String auths(Map<String, Object> data,String deptCode) {
        String traceid = UUID.randomUUID().toString();
        try {

            String resp = "";
            Map<String, Object> heads = new HashMap<>();


            heads.put("dc", deptCode);
            heads.put("traceid", traceid);



            if (data.containsKey("isEmbed") && Boolean.parseBoolean(data.get("isEmbed").toString())) {
                EmbedJwtToken ejwt = new EmbedJwtToken();
                boolean valid = ejwt.validateToken(data.get("token").toString());

                if (!valid) {
                    return "Invalid Authentication";
                } else {
                    data.putAll(new HeaderSecurity().getEmbedDetails(data.get("userName").toString(),deptCode,data.get("keyInfo").toString(),traceid));
                }

            } else {
                SimpleAuthImpl i = new SimpleAuthImpl();
                Map<String,Object> u = i.authenticate(data);

                if (u==null) {
                    return "Invalid Authentication";
                }
                data.putAll(u);
            }




            Map<String, Object> user = new CommonConfig().getUserInfo(data.get("userName").toString());

            Map<String, Object> additionalHeaders = new HashMap<>();

            data.put("additionalHeaders", additionalHeaders);
            data.put("token", user.get("token").toString());
            data.put("auth-token", user.get("token").toString());
            data.put("traceid", traceid);

            return data.toString();
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
                    traceid,deptCode, e);
            return null;
        }
    }

    /*public String noauthenticated(Map<String, Object> data,String deptCode) {
        String traceid = UUID.randomUUID().toString();
        try {

            String resp = "";
            Map<String, Object> heads = new HashMap<>();


            heads.put("dc", deptCode);
            heads.put("traceid", traceid);

            data.putAll(new HeaderSecurity().getEmbedDetails(data.get("userName").toString(),deptCode,data.get("keyInfo").toString(),traceid));

            Map<String, Object> user = new CommonConfig().getUserInfo(data.get("userName").toString());

            Map<String, Object> additionalHeaders = new HashMap<>();
            additionalHeaders.put("token", user.get("token").toString());

            data.put("additionalHeaders", additionalHeaders);
            data.put("token", user.get("token").toString());
            data.put("client_columns", "token");

            return new HeaderSecurity().getSecure(data,deptCode,traceid);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,DefaultAuthenticateImpl.class, e.getMessage(),
                    traceid,deptCode, e);
            return null;
        }
    }*/

}

