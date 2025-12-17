package com.security.services;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.IAuthentication;
import com.aivhub.security.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.security.Be;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;


public class SimpleAuthImpl implements IAuthentication {

    DataSource dataSource = GetBean.context != null ? (DataSource) GetBean.context.getBean("dataSource1") : null;

    String deptCode;
    String traceid;

    @Override
    public void setApplicationContextAndDatasource(ApplicationContext context) {
        this.dataSource = (DataSource) context.getBean("dataSource1");
    }

    @Override
    public void setSource(DataSource dataSource, String deptCode, String traceid) {
        try {
            Class<?> implClass1 = Class.forName("com.aiv.b.Bx");

            Class<?>[] argumentTypes = {String.class};

            Method method1 = implClass1.getDeclaredMethod("getBean",argumentTypes);

            this.dataSource = dataSource != null ? (DataSource) method1.invoke(implClass1.getDeclaredConstructor().newInstance(),"dataSource1") : dataSource;
            this.deptCode  =deptCode;
            this.traceid = traceid;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,SimpleAuthImpl.class, e.getMessage(),"AUTHENTICATION",deptCode, e);
        }
    }

    @Override
    public List<Map<String, Object>> getAllUsers(String deptCode, Map<String, Object> map) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getAllUsers(map.get("owner").toString(), deptCode);
    }

    @Override
    public List<Map<String, Object>> getAllRoles(String deptCode, Map<String, Object> map) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getAllRoles(deptCode);
    }

    @Override
    public List<Map<String, Object>> getAllDepartments(String deptCode, Map<String, Object> data) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getAllDepartments(deptCode);
    }

    @Override
    public Map<String, Object> authenticate(Map<String, Object> map) {

        try {

                SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
                String userId = service.validatePassword(map.get("userName").toString(), map.get("password").toString(),map.get("deptCode").toString(),map.get("salt").toString());
                User userInfo = new User();
                map.remove("slat");
                if (!userId.equals("0")) {


                    return map;//new UtilServices().getAuthTimeUser(map,dataSource,this.deptCode,traceid);

                    /*Map<String, Object> at= service.getUserRoleFeatures(map.get("userName").toString(),map.get("deptCode").toString());

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
                    userInfo.setDepartment(map.get("deptCode").toString());
                    InputStream inputStream = Files.newInputStream(Paths.get( GetBean.REPOSITORYLOCATION_PATH+"/econfig/"+"user_default.properties"));
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
                        userInfo.setUserType(at.containsKey("userType") ? at.get("userType").toString() : p.get("demo_userType").toString());

                    }*/
                }

               /* Map<String, Object> all = new ObjectMapper().convertValue(userInfo, Map.class);
                all.put("roles", service.getRoleNamesForUser(userInfo.getUserName().toString(),userInfo.getDepartment()));

                all.putAll(new DefaultAuthenticateImpl().authenticated(all,deptCode,traceid));*/

                return null;

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,SimpleAuthImpl.class, e.getMessage(),"AUTHENTICATION",map.get("deptCode").toString(), e);
        }

        return null;
    }

    @Override
    public Map<String, Object> embedAuthenticate(HttpServletRequest req, HttpServletResponse res, Map<String, Object> map) {
        try {

            String deptCode = null;
            JSONObject jsonObj = null;
            String uname = null;
            uname = map.containsKey("userName") ? map.get("userName").toString() : null;

            Map<String, Object> user = new HashMap<>();
            if(uname !=null){
                user = getUserByName(uname, deptCode,null);
            }

            String pwd = jsonObj.has("password") ? jsonObj.getString("password") : jsonObj.getString("token");


            Map<String, Object> d = new HashMap<>();
            d.put("userName",uname);
            d.put("password",pwd);
            d.put("deptCode",deptCode);
            user = authenticate(d);

            user.put("owner",uname);

            //user.putAll(new DefaultAuthenticateImpl().authenticated(user,deptCode));

            return user;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,SimpleAuthImpl.class, e.getMessage(),"AUTHENTICATION",map.get("deptCode").toString(), e);
            return null;
        }
    }

    @Override
    public boolean isAuthorize(Map<String, Object> headers) {
        JSONObject js = null;
        try {
             //js = new JSONObject(new HeaderSecurity().fromHexString(headers.get("additional_token").toString()));
            return CommonConfig.isAuthneticated(headers.get("token").toString(),headers.get("dc").toString(),headers.get("traceid").toString());
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,SimpleAuthImpl.class, e.getMessage(),"AUTHENTICATION",headers.get("dc").toString(), e);
            return false;
        }


    }

    @Override
    public int changePassword(Map<String, Object> user, String deptCode, String traceid) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.changePassword(user,deptCode,traceid);
    }

    @Override
    public List<Map<String, Object>> selectUsersOfRole(String role, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getUserbyRole(role, deptCode);
    }

    @Override
    public List<Map<String, Object>> selectRolesOfUser(String user, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getRolesForUser(user,deptCode);
    }

    @Override
    public boolean isRoleExists(String name,String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.isRoleExists(name,deptCode);
    }

    @Override
    public boolean isUserExists(String name,String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.isUserExist(name);
    }

    @Override
    public Map<String, Object> getUserByName(String userName,String deptCode, Map<String, Object> map) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getUserByName(userName,deptCode);
    }

    @Override
    public Map<String, Object> getRoleByName(String roleName,String deptCode, Map<String, Object> map) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getRoleByName(roleName,deptCode);
    }

    @Override
    public int CreateEditUser(Map<String, Object> data, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);

        if (data.containsKey("password") && data.get("password") != null && data.get("password").toString().trim() != "") {
            try {
                data.put("password",new Be().encrypt(data.get("password").toString(), Be.EncKey));
                data.put("pwdChngFlag",true);
            } catch (GeneralSecurityException e) {
                AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "Password Encryption failed: " + data.get("userName").toString(), traceid, deptCode, e);
                return -1;
            }
        } else {
            data.put("pwdChngFlag",false);
        }

        if (data.containsKey("editFlag") && Boolean.parseBoolean(data.get("editFlag").toString()) &&
        data.containsKey("updateProfile") && Boolean.parseBoolean(data.get("updateProfile").toString())) {
            return service.updateUserProfile(data);
        } else if (data.containsKey("editFlag") && Boolean.parseBoolean(data.get("editFlag").toString()) &&
                data.containsKey("updatePersonalInfo") && Boolean.parseBoolean(data.get("updatePersonalInfo").toString())) {
            return service.updateUserPersonalizeInfo(data);
        } else if (data.containsKey("editFlag") && Boolean.parseBoolean(data.get("editFlag").toString())) {
            return service.updateUser(data,deptCode);
        } else {
            return service.CreateUser(data,deptCode);
        }

    }

    @Override
    public int CreateEditRole(Map<String, Object> data, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        if (data.containsKey("editFlag") && Boolean.parseBoolean(data.get("editFlag").toString())) {
            return service.updateRole(data,deptCode);
        } else {
            return service.CreateRole(data,deptCode);
        }
    }

    @Override
    public int CreateEditDepartment(Map<String, Object> data, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        if (data.containsKey("editFlag") && Boolean.parseBoolean(data.get("editFlag").toString())) {
            return service.UpdateDepartment(data,deptCode);
        } else {
            int a =  service.CreateDepartment(data,deptCode);

            if (a > 0) {

            String fileName = "ai_postgresql_general.sql";
                String content = null;
                try {
                    InputStream inputStream = Files.newInputStream(Paths.get( GetBean.REPOSITORYLOCATION_PATH+"/econfig/"+fileName));
                    content = IOUtils.toString(inputStream);
                    //content = IOUtils.toString(SimpleAuthImpl.class.getClassLoader().getResourceAsStream(fileName));
                } catch (IOException e) {
                    e.printStackTrace();
                }
                content = content.replaceAll("XXXXX", data.get("deptCode").toString());
            Resource resource = new ByteArrayResource(content.getBytes());

            ResourceDatabasePopulator databasePopulator = new ResourceDatabasePopulator(resource);
                databasePopulator.setSeparator("//@");
                databasePopulator.execute(this.dataSource);

                Map<String, Object> user = new HashMap<>();
                User userInfo = new User();

                    userInfo.setFirstName(data.get("userName").toString());
                    userInfo.setLastName(null);
                    userInfo.setUserName(data.get("userName").toString());
                    userInfo.setStatus("Active");
                    userInfo.setUserType("INT");
                    userInfo.setEmail(data.containsKey("email") && data.get("email") != null ? data.get("email").toString() : "");
                    userInfo.setHomeFolder("/" + data.get("userName").toString());
                    userInfo.setBackupUserId("");
                    userInfo.setManagerUserId("");
                    userInfo.setDefault_dashboard("");
                    userInfo.setLanding_page("Documents/Reports");
                    userInfo.setLocale("en");
                    userInfo.setTimezone("SYSTEM");
                    userInfo.setNotification("0");
                    userInfo.setShowname("1");
                    userInfo.setShowimage("1");
                    userInfo.setBackupFor(null);
                    //userInfo.setPa("password", at.containsKey("password") ? at.get("password").toString() : null);
                    userInfo.setDepartment(data.get("deptCode").toString());

                Properties p = null;
                try {
                    InputStream inputStream = Files.newInputStream(Paths.get( GetBean.REPOSITORYLOCATION_PATH+"/econfig/"+"user_default.properties"));
                     p = new Properties();
                    p.load(inputStream);
                   // p = PropertiesLoaderUtils.loadProperties(new ClassPathResource(GetBean.REPOSITORYLOCATION_PATH+"/econfig/"+"user_default.properties"));
                } catch (IOException e) {
                    e.printStackTrace();
                }
                Iterator<Object> iter = p.keySet().iterator();

                        userInfo.setAdhocOption(p.get("admin_adhocOption").toString());
                        userInfo.setAdminOption(p.get("admin_adminOption").toString());
                        userInfo.setAlertsOption(p.get("admin_alertsOption").toString());
                        userInfo.setAnnotationOption(p.get("admin_annotationOption").toString());
                        userInfo.setDashboardOption(p.get("admin_dashboardOption").toString());
                        userInfo.setDatasetOption(p.get("admin_datasetOption").toString());
                        userInfo.setMappingOption(p.get("admin_mappingOption").toString());
                        userInfo.setMergeReportOption(p.get("admin_mergeReportOption").toString());
                        userInfo.setMessageOption(p.get("admin_messageOption").toString());
                        userInfo.setNotificationOption(p.get("admin_notificationOption").toString());
                        userInfo.setParameterOption(p.get("admin_parameterOption").toString());
                        userInfo.setQuickRunOption(p.get("admin_quickRunOption").toString());
                        userInfo.setReportOption(p.get("admin_reportOption").toString());
                        userInfo.setRequestOption(p.get("admin_requestOption").toString());
                        userInfo.setResourceOption(p.get("admin_resourceOption").toString());
                        userInfo.setScheduleOption(p.get("admin_scheduleOption").toString());
                        userInfo.setWebhookOption(p.get("admin_webhookOption").toString());
                        userInfo.setUserType(p.get("admin_userType").toString());

                user = new ObjectMapper().convertValue(userInfo, Map.class);
                user.put("password", data.get("password").toString());
                CreateEditUser(user,data.get("deptCode").toString());
            }
            return a;

        }
    }

    @Override
    public List<Map<String, Object>> getAlldepartmentsWithAdmin(String owner, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return  service.getAllDeptWithAdmins();
    }

    @Override
    public int deleteDeptById(String owner, Map<String, Object> deptId) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.deleteDeptById(owner,deptId);
    }

    @Override
    public int deleteUserById(String userName, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        deleteUser(userName,deptCode);
        return service.deleteUser(userName,deptCode);
    }

    @Override
    public int deleteRoleById(String roleName, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.deleteRole(roleName,deptCode);
    }

    @Override
    public Map<String, Object> getUserRoleFeatures(String userName, String deptCode) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
        return service.getUserRoleFeatures(userName,deptCode);

    }

    @Override
    public int updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource, deptCode, this.traceid);
        service.deleteRolesForUser(userRoleData.get("userName").toString());
        service.addRolesForUser(userRoleData);
        return 1;
    }

    @Override
    public int updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
        SimpleAuthService service = new SimpleAuthService(this.dataSource, deptCode, this.traceid);
        service.deleteUsersForRole(userRoleData.get("roleName").toString());
        service.addUsersForRole(userRoleData);
        return 1;
    }

    @Override
    public boolean deptExists(String deptCode, String traceid) {
        return false;
    }

    public Map<String, Object> getUserDetails(String userName, String deptCode, DataSource dataSource, String traceid) {
        SimpleAuthService service = new SimpleAuthService(dataSource, "", traceid);
        return service.getUserDetails(userName);
    }

    @Override
    public Map<String, Object> getAuthAfterTimeUser(String userName, String dc, String traceid) {
        try {
            SimpleAuthService service = new SimpleAuthService(dataSource, dc, traceid);
            User userInfo = new User();

            Map<String, Object> user = getUserDetails(userName, dc, dataSource, traceid);

            Map<String, Object> at = service.getUserRoleFeatures(user.get("userName").toString(), user.get("department").toString());

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, SimpleAuthImpl.class, "user info is: " + at.toString(), traceid, dc, null);

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
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, SimpleAuthImpl.class,
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
                userInfo.setWebhookOption(at.containsKey("webhookOption") && at.get("webhookOption") !=null ? at.get("webhookOption").toString() : "0");
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
                userInfo.setWebhookOption(at.containsKey("webhookOption")  && at.get("webhookOption") !=null ? at.get("webhookOption").toString() : "0");
                userInfo.setUserType(at.containsKey("userType") ? at.get("userType").toString() : p.get("demo_userType").toString());

            }
            Map<String, Object> rs = new ObjectMapper().convertValue(userInfo, Map.class);
            List<Map<String, Object>> rls =  selectRolesOfUser(userName,dc);

            String roles = rls != null ? rls.stream().map(h -> h.get("name").toString()).collect(Collectors.joining(",")) : null;
            rs.put("roles", roles);
            rs.put("owner", user.get("userName").toString());

            return rs;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR, SimpleAuthImpl.class,
                    "Error while getting user ","login User",deptCode, null);
            return null;
        }
    }

    @Override
    public String generateEmbedToken(Map<String, Object> data, String deptCode, String traceid) {
        return "";
    }


    public int deleteUser(String userNameIN, String deptCode) {
        try {
            SimpleAuthService service = new SimpleAuthService(this.dataSource,deptCode,traceid);
            service.deleteRolesForUser(userNameIN);
            return 1;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR, SimpleAuthImpl.class,
                    "Error while getting user list","Delete User",deptCode, null);
            return -1;
        }

    }
}
