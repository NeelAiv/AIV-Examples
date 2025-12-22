package com.example.SAMLwOkta;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.HeaderSecurity;
import com.aivhub.security.IAuthentication;
import com.example.SAMLwOkta.service.OktaService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class SamlAuthenticationImpl2 implements IAuthentication {

    private static OktaService staticOktaService;
    private static ResourceLoader staticResourceLoader;
    private static Properties userDefaults;
    private static String userDefaultsPath;
    private static SamlAuthenticationImpl2 instance;

    private final JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();
    private String traceid = "SAML_AUTH_SYSTEM";
    private String deptCode = "Default";

    public SamlAuthenticationImpl2() {
        System.out.println("A new SamlAuthenticationImpl2 object has been constructed.");
    }

    @Autowired
    public void setStaticDependencies(OktaService oktaService, ResourceLoader resourceLoader) {
        SamlAuthenticationImpl2.staticOktaService = oktaService;
        SamlAuthenticationImpl2.staticResourceLoader = resourceLoader;
    }

    @PostConstruct
    private void init() {
        instance = this;
    }

    @Override
    public void setApplicationContextAndDatasource(ApplicationContext context) {

        if (SamlAuthenticationImpl2.staticOktaService == null) {
            System.err.println("WARN: Spring dependency injection did not run. Fetching beans from AIV context as a fallback.");
            SamlAuthenticationImpl2.staticOktaService = context.getBean(OktaService.class);
            SamlAuthenticationImpl2.staticResourceLoader = context;
        }

        Environment environment = context.getEnvironment();
        SamlAuthenticationImpl2.userDefaultsPath = environment.getProperty("sso.user-defaults-path");
        SamlAuthenticationImpl2.userDefaults = loadPropertiesFile(SamlAuthenticationImpl2.userDefaultsPath);
    }

    public static SamlAuthenticationImpl2 getInstance() {
        if (instance == null) {
            System.err.println("WARN: getInstance() called before Spring initialization. Returning a new, unmanaged instance.");
            return new SamlAuthenticationImpl2();
        }
        return instance;
    }

    private Properties loadPropertiesFile(String resourcePath) {
        Properties properties = new Properties();
        if (staticResourceLoader == null || resourcePath == null) {
            System.err.println("Cannot load properties: staticResourceLoader or path is null.");
            return properties;
        }
        try (InputStream inputStream = staticResourceLoader.getResource(resourcePath).getInputStream()) {
            properties.load(inputStream);
        } catch (IOException e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, "SamlAuthenticationImpl2", "Failed to load properties resource: " + resourcePath, traceid, deptCode, e);
        }
        return properties;
    }


    private Properties loadUserDefaults() {
        Properties properties = new Properties();
        try (InputStream input = new ClassPathResource("user_default.properties").getInputStream()) {
            properties.load(input);
        } catch (IOException e) {
            System.err.println("FATAL: Could not load user_default.properties file. User provisioning will fail.");
            e.printStackTrace();
        }
        return properties;
    }

    private Map<String, Object> buildFullAivUserProfile(Map<String, Object> oktaUser) {
        if (oktaUser == null || !oktaUser.containsKey("profile")) {
            return null;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) oktaUser.get("profile");
        String userName = (String) profile.get("login");

        Map<String, Object> fullProfile = new HashMap<>();

        fullProfile.put("userName", userName);
        fullProfile.put("firstName", profile.get("firstName"));
        fullProfile.put("lastName", profile.get("lastName"));
        fullProfile.put("email", profile.get("email"));
        fullProfile.put("status", oktaUser.get("status"));

        fullProfile.put("userType", "INT");
        fullProfile.put("department", "Default");
        fullProfile.put("homeFolder", "/" + userName);
        fullProfile.put("theme", "Default");
        fullProfile.put("locale", "en");
        fullProfile.put("timezone", "SYSTEM");
        fullProfile.put("showname", "1");
        fullProfile.put("showimage", "1");
        fullProfile.put("notification", "0");
        fullProfile.put("landing_page", "Documents/Reports");
        fullProfile.put("default_dashboard", "");
        fullProfile.put("managerUserId", "");
        fullProfile.put("backupUserId", "");

        fullProfile.put("adminOption", "2");
        fullProfile.put("scheduleOption", "2");
        fullProfile.put("datasetOption", "2");
        fullProfile.put("quickRunOption", "2");
        fullProfile.put("alertsOption", "2");
        fullProfile.put("mappingOption", "2");
        fullProfile.put("dashboardOption", "2");
        fullProfile.put("webhookOption", "2");
        fullProfile.put("mergeReportOption", "2");
        fullProfile.put("reportOption", "2");
        fullProfile.put("parameterOption", "2");
        fullProfile.put("resourceOption", "2");
        fullProfile.put("annotationOption", "2");
        fullProfile.put("adhocOption", "2");
        fullProfile.put("messageOption", "2");
        fullProfile.put("notificationOption", "2");
        fullProfile.put("requestOption", "2");

        return fullProfile;
    }

    private OktaService getOktaService() {
        if (staticOktaService == null) {
            throw new IllegalStateException("FATAL: The static OktaService was not initialized. Spring dependency injection failed.");
        }
        return staticOktaService;
    }


    @Override
    public void setSource(DataSource ds, String deptCode, String traceid) {
        this.deptCode = deptCode;
        this.traceid = traceid;
    }


    @Override
    public List<Map<String, Object>> getAllUsers(String deptCode, Map<String, Object> data) {
//        System.out.println(">>> METHOD CALLED: getAllUsers");
//        System.out.println("getAllUsers: Fetching all users from Okta and transforming to AIV format.");
        OktaService service = getOktaService();
        if (service == null) {
            System.err.println("FATAL: oktaService is null in getAllUsers. Injection failed.");
            return List.of();
        }

        List<Map<String, Object>> oktaUsers = service.getAllUsers();
        if (oktaUsers == null) {
            return List.of();
        }

        List<Map<String, Object>> aivUsers = oktaUsers.stream()
                .map(this::buildFullAivUserProfile)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

//        System.out.println("Aiv users: " + aivUsers);

//        System.out.println("getAllUsers: Successfully transformed " + aivUsers.size() + " users to AIV format.");

        return aivUsers;
    }


    @Override
    public List<Map<String, Object>> getAllRoles(String deptCode, Map<String, Object> data) {
        System.out.println(">>> METHOD CALLED: getAllRoles");

        Map<String, Object> adminRole = new HashMap<>();

        adminRole.put("name", "Administrator");
        adminRole.put("roleName", "Administrator");
        adminRole.put("description", "Administrator role for SAML users");
        adminRole.put("department", deptCode);
        adminRole.put("status", "Active");

        adminRole.put("adminOption", "2");
        adminRole.put("adhocOption", "2");
        adminRole.put("reportOption", "2");
        adminRole.put("dashboardOption", "2");
        adminRole.put("datasetOption", "2");
        adminRole.put("scheduleOption", "2");
        adminRole.put("alertsOption", "2");
        adminRole.put("parameterOption", "2");
        adminRole.put("resourceOption", "2");
        adminRole.put("annotationOption", "2");
        adminRole.put("mappingOption", "2");
        adminRole.put("messageOption", "2");
        adminRole.put("webhookOption", "2");
        adminRole.put("quickRunOption", "2");
        adminRole.put("mergeReportOption", "2");
        adminRole.put("notificationOption", "2");
        adminRole.put("requestOption", "2");

//        System.out.println("getAllRoles: Returning Administrator role: " + adminRole);

        return List.of(adminRole);
    }

    @Override
    public List<Map<String, Object>> getAllDepartments(String deptCode, Map<String, Object> data) {
//        System.out.println(">>> METHOD CALLED: getAllDepartments");
        Map<String, Object> defaultDepartment = new HashMap<>();

        defaultDepartment.put("deptcode", "Default");
        defaultDepartment.put("deptname", "Default Department");
        defaultDepartment.put("status", "Active");

//        System.out.println("getAllDepartments: Returning: " + List.of(defaultDepartment));

        return List.of(defaultDepartment);
    }

    @Override
    public Map<String, Object> authenticate(Map<String, Object> data) {
//        System.out.println("Executing 'authenticate' method for user: " + data.get("userName"));
//        System.out.println("Got data: " + data);

        String userName = (String) data.get("userName");
//        System.out.println("Found username in authnenticate: " + userName);
        if (userName == null || userName.trim().isEmpty()) {
            System.err.println("authenticate: userName is required");
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Username is required");
            return errorResponse;
        }

        Map<String, Object> response = new HashMap<>(data);
        if (!data.containsKey("token") || data.get("token") == null) {
            String token = jwtTokenUtil.generateToken(userName, "-1");
            response.put("token", token);
            response.put("auth-token", token);
//            System.out.println("Generated new token for user: " + userName);
        } else {
            String existingToken = data.get("token").toString();
            if (jwtTokenUtil.validateToken(existingToken)) {
//                System.out.println("Existing token is valid for user: " + userName);
            } else {
                String newToken = jwtTokenUtil.generateToken(userName, "-1");
                response.put("token", newToken);
                response.put("auth-token", newToken);
//                System.out.println("Existing token was invalid. Generated new token for user: " + userName);
            }
        }
        response.putIfAbsent("status", "success");
        response.putIfAbsent("deptCode", "Default");
        response.putIfAbsent("dc", "Default");
        response.putIfAbsent("userType", "INT");

        OktaService service = getOktaService();
        if (service != null) {
            Map<String, Object> oktaUser = service.getUserByName(userName);
            if (oktaUser != null && oktaUser.containsKey("profile")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> profile = (Map<String, Object>) oktaUser.get("profile");
                response.putIfAbsent("firstName", profile.getOrDefault("firstName", ""));
                response.putIfAbsent("lastName", profile.getOrDefault("lastName", ""));
                response.putIfAbsent("email", profile.getOrDefault("email", userName));
            }
        }

//        System.out.println("Response from authenticate: " + response);
        return response;
    }

    @Override
    public Map<String, Object> embedAuthenticate(HttpServletRequest req, HttpServletResponse res, Map<String, Object> data) {
        try {
            String deptCode = data.containsKey("deptCode") ? data.get("deptCode").toString() : null;
            String uname = data.containsKey("userName") ? data.get("userName").toString() : null;

            if (uname == null) {
                return null;
            }

            Map<String, Object> user = getUserByName(uname, deptCode, null);
            if (user == null) {
                return null;
            }

            String pwd = data.containsKey("password") ? data.get("password").toString() :
                    data.containsKey("token") ? data.get("token").toString() : null;

            if (pwd == null) {
                return null;
            }

            Map<String, Object> authData = new HashMap<>();
            authData.put("userName", uname);
            authData.put("password", pwd);
            authData.put("deptCode", deptCode);

            user = authenticate(authData);
            if (user != null) {
                user.put("owner", uname);
            }

            return user;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR,
                    SamlAuthenticationImpl2.class, e.getMessage(), "AUTHENTICATION",
                    data.get("deptCode").toString(), e);
            return null;
        }
    }

    @Override
    public boolean isAuthorize(Map<String, Object> headers) {
//        System.out.println("--- [isAuthorize Check START] ---");
//        System.out.println("Headers outside: " + headers);
        try {
            headers.forEach((key, value) -> System.out.println("Header: '" + key + "' = '" + value + "'"));

            String token = (String) headers.get("token");

            if (token == null || token.trim().isEmpty()) {
                token = (String) headers.get("token");
//                System.out.println("DEBUG: Using fallback token from 'token' field: " + token);
                return false;
            }
            if (token == null || token.trim().isEmpty()) {
//                System.out.println("DEBUG: No token found in token field 1");
                return false;
            }


            String deptCode = (String) headers.get("dc");
            String traceId = (String) headers.get("traceid");

//            System.out.println("DEBUG: Final JWT token to validate: " + token);
//            System.out.println("DEBUG: Token length: " + (token != null ? token.length() : "null"));

            if (token == null || token.trim().isEmpty()) {
//                System.err.println("No token found in token field 2");
//                System.out.println("--- [isAuthorize Check END] ---");
                return false;
            }

//            System.out.println("Token found for validation: " + token);
            boolean isAuthenicated = isAuthneticated(token, traceId, deptCode);
//            System.out.println("DEBUG: isAuthenticated result: " + isAuthenicated);

            return isAuthenicated;

        } catch (Exception e) {
//            System.out.println("DEBUG: Exception in isAuthorize: " + e.getMessage());
            e.printStackTrace();
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR,
                    SamlAuthenticationImpl2.class, e.getMessage(), "AUTHENTICATION",
                    headers.get("dc") != null ? headers.get("dc").toString() : "unknown", e);
            return false;
        }
    }

    public static Boolean isAuthneticated(String token,String deptCode,String traceid) {
        try {

//            System.out.println("In in Authenticated..........");
            return new JwtTokenUtil().validateToken(token);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, SamlAuthenticationImpl2.class, e.getMessage(),
                    traceid,deptCode, e);
            return false;
        }
    }

    @Override
    public int changePassword(Map<String, Object> user, String deptCode, String traceid) {
        return 0;
    }

    @Override
    public List<Map<String, Object>> selectUsersOfRole(String role, String department) {
//        System.out.println(">>> METHOD CALLED: selectUsersOfRole for role: " + role);
        OktaService service = getOktaService();
        if (service == null) {
            System.err.println("selectUsersOfRole: OktaService not available");
            return List.of();
        }

        List<Map<String, Object>> allUsers = service.getAllUsers();
//        System.out.println("selectUsersOfRole: Returning " + allUsers.size() + " users for role: " + role);
        return allUsers;
    }

    @Override
    public List<Map<String, Object>> selectRolesOfUser(String username, String department) {
        Map<String, Object> defaultRole = new HashMap<>();
        defaultRole.put("name", "Administrator");
        defaultRole.put("roleDescription", "Default SAML Administrator Role");
        defaultRole.put("department", department != null ? department : "Default");

//        System.out.println("selectRolesOfUser: Returning default role for user: " + username);
//        System.out.println("Select roles of users: " + defaultRole);
        return List.of(defaultRole);
    }

    @Override
    public boolean isRoleExists(String name, String deptCode) {
//        System.out.println(">>> METHOD CALLED: isRoleExists for role: " + name);
        boolean exists = "Administrator".equalsIgnoreCase(name)
                || "Admin".equalsIgnoreCase(name)
                || "Default".equalsIgnoreCase(name);
//        System.out.println("isRoleExists: " + name + " = " + exists);
        return exists;
    }

    @Override
    public boolean isUserExists(String username, String deptCode) {
//        System.out.println(">>> METHOD CALLED: isUserExists for user: " + username);
        OktaService service = getOktaService();
        if (service == null) {
            System.err.println("isUserExists: OktaService not available");
            return false;
        }

        Map<String, Object> user = service.getUserByName(username);
        boolean exists = user != null;
//        System.out.println("isUserExists: " + username + " = " + exists);
        return exists;
    }

    @Override
    public Map<String, Object> getUserByName(String userName, String deptCode, Map<String, Object> data) {
//        System.out.println(">>> METHOD CALLED: getUserByName for: " + userName);
        
        OktaService service = getOktaService();
        Map<String, Object> oktaUser = null;
        if (service != null) {
            oktaUser = service.getUserByName(userName);
//            System.out.println("User by Name in oktaUser: " + oktaUser);
        }

        if (oktaUser != null && oktaUser.containsKey("profile")) {
            return buildFullAivUserProfile(oktaUser);
        }

        return buildDefaultUserProfile(userName, deptCode != null ? deptCode : "Default");
    }

    private Map<String, Object> buildDefaultUserProfile(String userName, String deptCode) {
        Map<String, Object> userProfile = new HashMap<>();
        
        userProfile.put("userName", userName);
        userProfile.put("owner", userName);
        userProfile.put("email", userName);
        userProfile.put("firstName", extractFirstName(userName));
        userProfile.put("lastName", extractLastName(userName));
        userProfile.put("status", "Active");
        userProfile.put("userType", "INT");
        userProfile.put("department", deptCode);
        userProfile.put("deptCode", deptCode);
        userProfile.put("dc", deptCode);
        userProfile.put("homeFolder", "/" + userName);

        userProfile.put("theme", "Default");
        userProfile.put("locale", "en");
        userProfile.put("timezone", "SYSTEM");
        userProfile.put("showname", "1");
        userProfile.put("showimage", "1");
        userProfile.put("notification", "0");
        userProfile.put("landing_page", "Documents/Reports");
        userProfile.put("default_dashboard", "");
        userProfile.put("managerUserId", "");
        userProfile.put("backupUserId", "");
        userProfile.put("roles", "Administrator");
        
        userProfile.put("adminOption", "2");
        userProfile.put("scheduleOption", "2");
        userProfile.put("datasetOption", "2");
        userProfile.put("quickRunOption", "2");
        userProfile.put("alertsOption", "2");
        userProfile.put("mappingOption", "2");
        userProfile.put("dashboardOption", "2");
        userProfile.put("webhookOption", "2");
        userProfile.put("mergeReportOption", "2");
        userProfile.put("reportOption", "2");
        userProfile.put("parameterOption", "2");
        userProfile.put("resourceOption", "2");
        userProfile.put("annotationOption", "2");
        userProfile.put("adhocOption", "2");
        userProfile.put("messageOption", "2");
        userProfile.put("notificationOption", "2");
        userProfile.put("requestOption", "2");
        
        return userProfile;
    }

    private String extractFirstName(String userName) {
        if (userName == null || userName.isEmpty()) {
            return "";
        }
        String[] parts = userName.split("@")[0].split("\\.");
        if (parts.length > 0) {
            return capitalize(parts[0]);
        }
        return capitalize(userName.split("@")[0]);
    }


    private String extractLastName(String userName) {
        if (userName == null || userName.isEmpty()) {
            return "";
        }
        String[] parts = userName.split("@")[0].split("\\.");
        if (parts.length > 1) {
            return capitalize(parts[1]);
        }
        return "";
    }

    private String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return "";
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }

    @Override
    public Map<String, Object> getRoleByName(String roleName, String deptCode, Map<String, Object> data) {
//        System.out.println(">>> METHOD CALLED: getRoleByName for role: " + roleName);

        if (!"Admin".equalsIgnoreCase(roleName) && !"Administrator".equalsIgnoreCase(roleName)) {
//            System.out.println("getRoleByName: Role not found: " + roleName);
            return Map.of();
        }

        Map<String, Object> role = new HashMap<>();
        role.put("name", "Administrator");
        role.put("roleName", "Administrator");
        role.put("department", deptCode);
        role.put("status", "Active");
        role.put("description", "Full access admin role for SAML users");

        role.put("adminOption", "2");
        role.put("scheduleOption", "2");
        role.put("datasetOption", "2");
        role.put("quickRunOption", "2");
        role.put("alertsOption", "2");
        role.put("mappingOption", "2");
        role.put("dashboardOption", "2");
        role.put("webhookOption", "2");
        role.put("mergeReportOption", "2");
        role.put("reportOption", "2");
        role.put("parameterOption", "2");
        role.put("resourceOption", "2");
        role.put("annotationOption", "2");
        role.put("adhocOption", "2");
        role.put("messageOption", "2");
        role.put("notificationOption", "2");
        role.put("requestOption", "2");

//        System.out.println("getRoleByName: Returning complete role: " + role);
        return role;
    }

    @Override
    public int CreateEditUser(Map<String, Object> data, String deptCode) {
//        System.out.println(">>> METHOD CALLED: CreateEditUser");
//        System.out.println("Data: " + data);
        String username = data.get("userName") != null ? data.get("userName").toString() : null;

        if (username == null) {
            System.err.println("CreateEditUser: userName is required");
            return 0;
        }

//        System.out.println("CreateEditUser: SAML users are auto-provisioned. Skipping creation for: " + username);

        try {
            new HeaderSecurity().createFilesFolders(username, deptCode, "USER_MANAGEMENT");
//            System.out.println("CreateEditUser: Ensured home folder exists for: " + username);
            return 1;
        } catch (Exception e) {
            System.err.println("CreateEditUser: Failed to create home folder: " + e.getMessage());
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int CreateEditRole(Map<String, Object> data, String deptCode) {
//        System.out.println(">>> METHOD CALLED: CreateEditRole");
//        System.out.println("Data: " + data);
        String roleName = data.get("roleName") != null ? data.get("roleName").toString() : null;

        if (roleName == null) {
            System.err.println("CreateEditRole: roleName is required");
            return 0;
        }

        if ("Administrator".equalsIgnoreCase(roleName)) {
//            System.out.println("CreateEditRole: Allowing Administrator role creation for SAML");
            return 1;
        }

        return 0;
    }

    @Override
    public int CreateEditDepartment(Map<String, Object> data, String deptCode) {
//        System.out.println(">>> METHOD CALLED: CreateEditDepartment");
//        System.out.println("Data: " + data);
        String departmentName = data.get("deptCode") != null ? data.get("deptCode").toString() : null;

        if (departmentName == null) {
            System.err.println("CreateEditDepartment: deptCode is required");
            return 0;
        }

//        System.out.println("CreateEditDepartment: Departments are predefined in SAML setup: " + departmentName);
        return 0;
    }

    @Override
    public List<Map<String, Object>> getAlldepartmentsWithAdmin(String owner, String deptCode) {
        Map<String, Object> defaultDept = new HashMap<>();
        defaultDept.put("deptCode", "Default");
        defaultDept.put("deptName", "Default Department");
        defaultDept.put("admin", owner);
        defaultDept.put("status", "Active");

        return List.of(defaultDept);
    }

    @Override
    public int deleteDeptById(String owner, Map<String, Object> deptId) {
        return 0;
    }

    @Override
    public int deleteUserById(String owner, String deptCode) {
        return 0;
    }

    @Override
    public int deleteRoleById(String owner, String deptCode) {
        return 0;
    }

    @Override
    public Map<String, Object> getUserRoleFeatures(String userName, String deptCode) {
//        System.out.println(">>> METHOD CALLED: getUserRoleFeatures for: " + userName + " in dept: " + deptCode);

        OktaService service = getOktaService();
        if (service == null) {
            System.err.println("getUserRoleFeatures: OktaService is not available.");
            return Map.of();
        }

        Map<String, Object> oktaUser = service.getUserByName(userName);
        if (oktaUser == null || !oktaUser.containsKey("profile")) {
            System.err.println("getUserRoleFeatures: User not found in Okta: " + userName);
            return Map.of();
        }

        Map<String, Object> finalFeatures = new HashMap<>();

        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) oktaUser.get("profile");
        finalFeatures.put("userName", profile.get("login"));
        finalFeatures.put("firstName", profile.get("firstName"));
        finalFeatures.put("lastName", profile.get("lastName"));
        finalFeatures.put("email", profile.get("email"));
        finalFeatures.put("status", oktaUser.get("status"));

        finalFeatures.put("userType", "INT");
        finalFeatures.put("department", deptCode);
        finalFeatures.put("homeFolder", "/" + userName);
        finalFeatures.put("theme", "Default");
        finalFeatures.put("locale", "en");
        finalFeatures.put("timezone", "SYSTEM");
        finalFeatures.put("landing_page", "Documents/Reports");
        finalFeatures.put("default_dashboard", "");
        finalFeatures.put("managerUserId", "");
        finalFeatures.put("backupUserId", "");
        finalFeatures.put("showname", "1");
        finalFeatures.put("showimage", "1");
        finalFeatures.put("notification", "0");

        finalFeatures.put("adminOption", "2");
        finalFeatures.put("scheduleOption", "2");
        finalFeatures.put("datasetOption", "2");
        finalFeatures.put("quickRunOption", "2");
        finalFeatures.put("alertsOption", "2");
        finalFeatures.put("mappingOption", "2");
        finalFeatures.put("dashboardOption", "2");
        finalFeatures.put("webhookOption", "2");
        finalFeatures.put("mergeReportOption", "2");
        finalFeatures.put("reportOption", "2");
        finalFeatures.put("parameterOption", "2");
        finalFeatures.put("resourceOption", "2");
        finalFeatures.put("annotationOption", "2");
        finalFeatures.put("adhocOption", "2");
        finalFeatures.put("messageOption", "2");
        finalFeatures.put("notificationOption", "2");
        finalFeatures.put("requestOption", "2");

//        System.out.println("getUserRoleFeatures: Returning complete features: " + finalFeatures);

        return finalFeatures;
    }

    @Override
    public int updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
//        System.out.println(">>> METHOD CALLED: updateRolesForUser");
//        System.out.println("userRoleData: " + userRoleData);
//        System.out.println("updatedBy: " + updatedBy);
//
//        System.out.println("updateRolesForUser: Roles are managed in Okta. Returning success.");

        return 1;
    }

    @Override
    public int updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
//        System.out.println(">>> METHOD CALLED: updateUsersForRole");
//        System.out.println("userRoleData: " + userRoleData);
//        System.out.println("updatedBy: " + updatedBy);
//
//        System.out.println("updateUsersForRole: User-role assignments are managed in Okta. Returning success.");

        return 1;
    }

    @Override
    public boolean deptExists(String deptCode, String traceid) {
        boolean exists = "Default".equalsIgnoreCase(deptCode);
//        System.out.println("deptExists: " + deptCode + " = " + exists);
        return exists;
    }

    @Override
    public Map<String, Object> getAuthAfterTimeUser(String userName, String dc, String traceid) {
//        System.out.println("Building COMPLETE and RELIABLE profile defaults for: " + userName);

        Map<String, Object> userProfile = new HashMap<>();

        userProfile.put("adhocOption","2");
        userProfile.put("adminOption","2");
        userProfile.put("alertsOption", "2");
        userProfile.put("annotationOption","2");
        userProfile.put("backupUserId", "");
        userProfile.put("dashboardOption","2");
        userProfile.put("datasetOption","2");
        userProfile.put("default_dashboard","");
        userProfile.put("department",dc);
        userProfile.put("homeFolder", "/" + userName);
        userProfile.put("landing_page","Documents/Reports");
        userProfile.put("locale", "en");
        userProfile.put("managerUserId", "2");
        userProfile.put("mappingOption", "2");
        userProfile.put("mergeReportOption",  "2");
        userProfile.put("messageOption","2");
        userProfile.put("notification",  "2");
        userProfile.put("notificationOption", "2");
        userProfile.put("parameterOption", "2");
        userProfile.put("quickRunOption",  "2");
        userProfile.put("reportOption", "2");
        userProfile.put("requestOption", "2");
        userProfile.put("resourceOption", "2");
        userProfile.put("scheduleOption", "2");
        userProfile.put("webhookOption",  "2");
        userProfile.put("showimage",  "1");
        userProfile.put("showname",  "1");
        userProfile.put("status", "Active");
        userProfile.put("theme", "Default");
        userProfile.put("timezone", "SYSTEM");
        userProfile.put("userName", userName);
        userProfile.put("userType",  "INT");
        userProfile.put("roles", "Administrator");
        userProfile.put("owner", userName);

        OktaService service = getOktaService();
        if (service != null) {
            Map<String, Object> oktaUser = service.getUserByName(userName);
            if (oktaUser != null && oktaUser.containsKey("profile")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> profile = (Map<String, Object>) oktaUser.get("profile");
                userProfile.put("firstName", profile.getOrDefault("firstName", ""));
                userProfile.put("lastName", profile.getOrDefault("lastName", ""));
                userProfile.put("email", profile.getOrDefault("email", userName));
            }
        }

//        System.out.println("Final, complete User Profile: " + userProfile);
        return userProfile;
    }

    @Override
    public String generateEmbedToken(Map<String, Object> data, String deptCode, String traceid) {
        return "dummy-token";
    }
}