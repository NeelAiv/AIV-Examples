package com.example.KeycloakSecurity;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.IAuthentication;
import com.aivhub.security.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

@Service
public class UserInfoServices {

//    public Map<String, Object> getAuthTimeUser(Map<String, Object> map, DataSource dataSource,
//                                               String dc, String traceid) {
//        try {
//
//            SimpleAuthService service = new SimpleAuthService(dataSource, dc, traceid);
//            Map<String, Object> userInfo = new HashMap<>();
//
//            Map<String, Object> user = getUserDetails(map.get("userName").toString(), "", dataSource, traceid);
//            Map<String, Object> at = service.getUserRoleFeatures(user.get("userName").toString(), user.get("department").toString());
//            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, UserInfoServices.class, "user info is: " + at.toString(), traceid, dc, null);
//
//            userInfo.put("userName", at.containsKey("userName") && at.get("userName") != null ? at.get("userName").toString() : null);
//            userInfo.put("department", user.get("department").toString());
//            return new ObjectMapper().convertValue(userInfo, Map.class);
//        } catch (Exception e) {
//            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, UserInfoServices.class, e.getMessage(), traceid, dc, e);
//            return null;
//        }
//    }


    public Map<String, Object> getAuthAfterTimeUser(String userName, DataSource dataSource,
                                                    String dc, String traceid) {
        try {

            IAuthentication keycloakAuth = new KeycloakAuthImpl();
            keycloakAuth.setSource(null, dc, traceid);

            Map<String, Object> at = keycloakAuth.getUserByName(userName, dc, null);
            if (at == null) {
                throw new Exception("User not found in Keycloak: " + userName);
            }

            List<Map<String, Object>> rolesFromKeycloak = keycloakAuth.selectRolesOfUser(userName, dc);
            List<String> roleNames = rolesFromKeycloak.stream()
                    .map(role -> role.get("name").toString())
                    .collect(Collectors.toList());

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, UserInfoServices.class,
                    "User info for " + userName + ": " + at.toString() + " | Roles: " + roleNames, traceid, dc, null);


            User userInfo = new User();


            Map<String, Object> user = getUserDetails(userName, dc, dataSource, traceid);
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, UserInfoServices.class, "user info is: " + at.toString(), traceid, dc, null);

            userInfo.setFirstName(at.containsKey("firstName") && at.get("firstName") != null ? at.get("firstName").toString() : null);
            userInfo.setLastName(at.containsKey("lastName") && at.get("lastName") != null ? at.get("lastName").toString() : null);
            userInfo.setUserName(at.containsKey("userName") && at.get("userName") != null ? at.get("userName").toString() : null);
            userInfo.setStatus(at.containsKey("status") && at.get("status") != null ? at.get("status").toString() : "InActive");
            userInfo.setUserType(at.containsKey("userType") && at.get("userType") != null ? at.get("userType").toString() : "INT");
            userInfo.setEmail(at.containsKey("email") && at.get("email") != null ? at.get("email").toString() : null);
            userInfo.setHomeFolder(at.containsKey("homeFolder") && at.get("homeFolder") != null ? at.get("homeFolder").toString() : "/" + (at.containsKey("userName") ? at.get("userName").toString() : null));
            userInfo.setBackupUserId(at.containsKey("backupUserId") && at.get("backupUserId") != null ? at.get("backupUserId").toString() : "");
            userInfo.setManagerUserId(at.containsKey("managerUserId") && at.get("managerUserId") != null ? at.get("managerUserId").toString() : "");
            userInfo.setDefault_dashboard(at.containsKey("default_dashboard") && at.get("default_dashboard") != null ? at.get("default_dashboard").toString() : "");
            userInfo.setLanding_page(at.containsKey("landing_page") && at.get("landing_page") != null ? at.get("landing_page").toString() : "Documents/Reports");
            userInfo.setLocale(at.containsKey("locale") && at.get("locale") != null ? at.get("locale").toString() : "en");
            userInfo.setTimezone(at.containsKey("timezone") && at.get("timezone") != null ? at.get("timezone").toString() : "SYSTEM");
            userInfo.setNotification(at.containsKey("notification") ? at.get("notification").toString() : "0");
            userInfo.setShowname(at.containsKey("showname") && at.get("showname") != null ? at.get("showname").toString() : "1");
            userInfo.setShowimage(at.containsKey("showimage") && at.get("showimage") != null ? at.get("showimage").toString() : "1");
            userInfo.setBackupFor(at.containsKey("backupFor") && at.get("backupFor") != null ? at.get("backupFor").toString() : null);
            //userInfo.setPa("password", at.containsKey("password") ? at.get("password").toString() : null);
            userInfo.setDepartment(user.get("department").toString());

            InputStream inputStream = Files.newInputStream(Paths.get( GetBean.REPOSITORYLOCATION_PATH+"/econfig/user_default.properties"));

            JSONObject j = new JSONObject();
            j.put("Traceid", traceid);
            j.put("message", " Reading user Default properties is reuqired: "+ user.get("userName").toString());
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, UserInfoServices.class,
                    j.toString(),traceid,user.get("department").toString(), null);

            //Properties p = PropertiesLoaderUtils.loadProperties(new ClassPathResource("user_default.properties"));
            Properties p = new Properties();
            p.load(inputStream);
            Iterator<Object> iter = p.keySet().iterator();
            if (at.get("userName").toString().equalsIgnoreCase("admin")) {

                userInfo.setAdhocOption(at.containsKey("adhocOption") ? at.get("adhocOption").toString() : p.get("admin_adhocOption").toString());
                userInfo.setAdminOption(at.containsKey("adminOption") ? at.get("adminOption").toString() : p.get("admin_adminOption").toString());
                userInfo.setAlertsOption(at.containsKey("alertsOption") ? at.get("alertsOption").toString() : p.get("admin_alertsOption").toString());
                userInfo.setAnnotationOption(at.containsKey("annotationOption") ? at.get("annotationOption").toString() : p.get("admin_annotationOption").toString());
                userInfo.setDashboardOption(at.containsKey("dashboardOption") ? at.get("dashboardOption").toString() : p.get("admin_dashboardOption").toString());
                userInfo.setDatasetOption(at.containsKey("datasetOption") ? at.get("datasetOption").toString() : p.get("admin_datasetOption").toString());
                userInfo.setMappingOption(at.containsKey("mappingOption") ? at.get("mappingOption").toString() : p.get("admin_mappingOption").toString());
                userInfo.setMergeReportOption(at.containsKey("mergeReportOption") ? at.get("mergeReportOption").toString() : p.get("admin_mergeReportOption").toString());
                userInfo.setMessageOption(at.containsKey("messageOption") ? at.get("messageOption").toString() : p.get("admin_messageOption").toString());
                userInfo.setNotificationOption(at.containsKey("notificationOption") ? at.get("notificationOption").toString() : p.get("admin_notificationOption").toString());
                userInfo.setParameterOption(at.containsKey("parameterOption") ? at.get("parameterOption").toString() : p.get("admin_parameterOption").toString());
                userInfo.setQuickRunOption(at.containsKey("quickRunOption") ? at.get("quickRunOption").toString() : p.get("admin_quickRunOption").toString());
                userInfo.setReportOption(at.containsKey("reportOption") ? at.get("reportOption").toString() : p.get("admin_reportOption").toString());
                userInfo.setRequestOption(at.containsKey("requestOption") ? at.get("requestOption").toString() : p.get("admin_requestOption").toString());
                userInfo.setResourceOption(at.containsKey("resourceOption") ? at.get("resourceOption").toString() : p.get("admin_resourceOption").toString());
                userInfo.setScheduleOption(at.containsKey("scheduleOption") ? at.get("scheduleOption").toString() : p.get("admin_scheduleOption").toString());
                userInfo.setWebhookOption(at.containsKey("webhookOption") ? at.get("webhookOption").toString() : p.get("admin_webhookOption").toString());
                userInfo.setUserType(at.containsKey("userType") ? at.get("userType").toString() : p.get("admin_userType").toString());

            } else {
                userInfo.setAdhocOption(at.containsKey("adhocOption") ? at.get("adhocOption").toString() : p.get("demo_adhocOption").toString());
                userInfo.setAdminOption(at.containsKey("adminOption") ? at.get("adminOption").toString() : p.get("demo_adminOption").toString());
                userInfo.setAlertsOption(at.containsKey("alertsOption") ? at.get("alertsOption").toString() : p.get("demo_alertsOption").toString());
                userInfo.setAnnotationOption(at.containsKey("annotationOption") ? at.get("annotationOption").toString() : p.get("demo_annotationOption").toString());
                userInfo.setDashboardOption(at.containsKey("dashboardOption") ? at.get("dashboardOption").toString() : p.get("demo_dashboardOption").toString());
                userInfo.setDatasetOption(at.containsKey("datasetOption") ? at.get("datasetOption").toString() : p.get("demo_datasetOption").toString());
                userInfo.setMappingOption(at.containsKey("mappingOption") ? at.get("mappingOption").toString() : p.get("demo_mappingOption").toString());
                userInfo.setMergeReportOption(at.containsKey("mergeReportOption") ? at.get("mergeReportOption").toString() : p.get("demo_mergeReportOption").toString());
                userInfo.setMessageOption(at.containsKey("messageOption") ? at.get("messageOption").toString() : p.get("demo_messageOption").toString());
                userInfo.setNotificationOption(at.containsKey("notificationOption") ? at.get("notificationOption").toString() : p.get("demo_notificationOption").toString());
                userInfo.setParameterOption(at.containsKey("parameterOption") ? at.get("parameterOption").toString() : p.get("demo_parameterOption").toString());
                userInfo.setQuickRunOption(at.containsKey("quickRunOption") ? at.get("quickRunOption").toString() : p.get("demo_quickRunOption").toString());
                userInfo.setReportOption(at.containsKey("reportOption") ? at.get("reportOption").toString() : p.get("demo_reportOption").toString());
                userInfo.setRequestOption(at.containsKey("requestOption") ? at.get("requestOption").toString() : p.get("demo_requestOption").toString());
                userInfo.setResourceOption(at.containsKey("resourceOption") ? at.get("resourceOption").toString() : p.get("demo_resourceOption").toString());
                userInfo.setScheduleOption(at.containsKey("scheduleOption") ? at.get("scheduleOption").toString() : p.get("demo_scheduleOption").toString());
                userInfo.setWebhookOption(at.containsKey("webhookOption") ? at.get("webhookOption").toString() : p.get("admin_webhookOption").toString());
                userInfo.setUserType(at.containsKey("userType") ? at.get("userType").toString() : p.get("demo_userType").toString());

            }
            userInfo.setTheme(at.containsKey("theme") && at.get("theme") != null ? at.get("theme").toString() : "Default");

            Map<String, Object> rs = new ObjectMapper().convertValue(userInfo, Map.class);

            rs.put("type", "individual");
            rs.put("owner",at.get("userName").toString());
            rs.put("roles",null);
            rs.put("token","AIV");

            return rs;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, UserInfoServices.class, e.getMessage(), traceid, dc, e);
            return null;
        }
    }


    public Map<String, Object> getUserDetails(String userName, String deptCode, DataSource dataSource, String traceid) {
        return null;
    }

}
