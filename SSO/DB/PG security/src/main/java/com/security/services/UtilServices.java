package com.security.services;

import com.aivhub.logs.AuditLoggerUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

public class UtilServices {


    public Map<String, Object> getAuthTimeUser(Map<String, Object> map, DataSource dataSource,
                                               String dc, String traceid) {
        try {

            SimpleAuthService service = new SimpleAuthService(dataSource, dc, traceid);
            Map<String, Object> userInfo = new HashMap<>();

            Map<String, Object> user = getUserDetails(map.get("userName").toString(), "", dataSource, traceid);
            Map<String, Object> at = service.getUserRoleFeatures(user.get("userName").toString(), user.get("department").toString());
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, UtilServices.class, "user info is: " + at.toString(), traceid, dc, null);

            userInfo.put("userName", at.containsKey("userName") && at.get("userName") != null ? at.get("userName").toString() : null);
            userInfo.put("department", user.get("department").toString());
            return new ObjectMapper().convertValue(userInfo, Map.class);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, UtilServices.class, e.getMessage(), traceid, dc, e);
            return null;
        }
    }

    public Map<String, Object> getUserDetails(String userName, String deptCode, DataSource dataSource, String traceid) {
        SimpleAuthService service = new SimpleAuthService(dataSource, "", traceid);
        return service.getUserDetails(userName);
    }

}
