package com.example.KeycloakSecurity;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.IAuthentication;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.io.FileUrlResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;

import javax.sql.DataSource;
import java.util.*;
import java.util.stream.Collectors;

@DependsOn("getBean")
public class KeycloakAuthImpl implements IAuthentication {

    private String traceid;
    private String deptCode;
    private final RestUtils restUtils = new RestUtils();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> MAP_LIST_TYPE_REF = new TypeReference<>() {};
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<>() {};

    private String getAdminToken() {
        return new CommonUtility().getMasterRealmToken(this.traceid, this.deptCode);
    }

    private String getKeycloakAdminUrl() {
        String url = GetBean.keycloakUrl;
        return (url.endsWith("/") ? url.substring(0, url.length() - 1) : url) + "/admin/realms";
    }

    private String executeKeycloakGetRequest(String url) {
        Map<String, Object> headers = new HashMap<>();
        String authToken = new CommonUtility().getMasterRealmToken(this.traceid, "master");
        headers.put("Authorization", "Bearer " + authToken);

        String response = restUtils.getRequest(url, headers, this.traceid);

        if (response == null) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, this.getClass().getName(), "Keycloak API call failed, possibly due to expired token. Retrying...", this.traceid, this.deptCode, null);
            GetBean.adminLogin.remove("access_token");
            authToken = new CommonUtility().getMasterRealmToken(this.traceid, "master");
            headers.put("Authorization", "Bearer " + authToken);
            response = restUtils.getRequest(url, headers, this.traceid);
        }

        return response;
    }

    private String getUserId(String userName, String realm) {
        try {
            String url = getKeycloakAdminUrl() + "/" + realm + "/users?exact=true&username=" + userName;
            System.out.println("Url in getUserId: " + url);
            String response = executeKeycloakGetRequest(url);
            if (response == null) return null;

            List<Map<String, Object>> users = objectMapper.readValue(response, MAP_LIST_TYPE_REF);
            return (users != null && !users.isEmpty()) ? users.get(0).get("id").toString() : null;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to get user ID for " + userName, this.traceid, realm, e);
            return null;
        }
    }

    private Map<String, Object> buildAivUserProfile(Map<String, Object> keycloakUser, String realm) {
        Map<String, Object> aivUser = new HashMap<>();
        String username = keycloakUser.get("username").toString();

        try {
            List<Map<String, Object>> roles = selectRolesOfUser(username, realm);
            List<String> roleNames = roles.stream().map(r -> r.get("name").toString()).collect(Collectors.toList());
            boolean isAdmin = roleNames.stream().anyMatch(name -> "admin".equalsIgnoreCase(name));
            String permissionPrefix = isAdmin ? "admin_" : "demo_";

            Properties permissions = PropertiesLoaderUtils.loadProperties(new FileUrlResource(GetBean.REPOSITORYLOCATION_PATH + "/econfig/user_default.properties"));

            aivUser.put("userName", username);
            aivUser.put("firstName", keycloakUser.get("firstName"));
            aivUser.put("lastName", keycloakUser.get("lastName"));
            aivUser.put("email", keycloakUser.get("email"));
            aivUser.put("status", (boolean) keycloakUser.getOrDefault("enabled", false) ? "Active" : "Inactive");
            aivUser.put("department", realm);
            aivUser.put("deptCode", realm);
            aivUser.put("owner", username);
            aivUser.put("roles", String.join(",", roleNames));
            aivUser.put("homeFolder", "/" + username);
            aivUser.put("landing_page", "Documents/Reports");
            aivUser.put("locale", "en");
            aivUser.put("timezone", "SYSTEM");
            aivUser.put("notification", "0");
            aivUser.put("showname", "1");
            aivUser.put("showimage", "1");
//            aivUser.put("token", "AIV");

            for (String propName : permissions.stringPropertyNames()) {
                if (propName.startsWith(permissionPrefix)) {
                    String permissionKey = propName.substring(permissionPrefix.length());
                    aivUser.put(permissionKey, permissions.getProperty(propName));
                }
            }
            aivUser.putIfAbsent("userType", "INT");

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to build full profile for user " + username, this.traceid, realm, e);
            aivUser.put("userName", username);
            aivUser.put("status", "Inactive");
            aivUser.put("adminOption", "0");
        }
        return aivUser;
    }

    private Map<String, Object> transformKeycloakRoleToAivRole(Map<String, Object> keycloakRole, String realm) {
        Map<String, Object> aivRole = new HashMap<>();
        String roleName = keycloakRole.get("name").toString();

        try {
            boolean isAdminRole = "admin".equalsIgnoreCase(roleName) || "Administrator".equalsIgnoreCase(roleName);
            String permissionPrefix = isAdminRole ? "admin_" : "demo_";
            Properties permissions = PropertiesLoaderUtils.loadProperties(new FileUrlResource(GetBean.REPOSITORYLOCATION_PATH + "/econfig/user_default.properties"));

            aivRole.put("id", keycloakRole.get("id"));
            aivRole.put("name", roleName);
            aivRole.put("description", keycloakRole.get("description"));
            aivRole.put("department", realm);

            if (keycloakRole.containsKey("attributes")) {
                Map<String, Object> attributes = (Map<String, Object>) keycloakRole.get("attributes");
                if (attributes.containsKey("email")) {
                    List<String> emailList = (List<String>) attributes.get("email");
                    System.out.println("Email list: " + emailList);
                    if (emailList != null && !emailList.isEmpty()) {
                        aivRole.put("email", emailList.get(0));
                    }
                }
            }
            aivRole.putIfAbsent("email", "");


            for (String propName : permissions.stringPropertyNames()) {
                if (propName.startsWith(permissionPrefix)) {
                    String permissionKey = propName.substring(permissionPrefix.length());
                    if (!"userType".equalsIgnoreCase(permissionKey)) {
                        aivRole.put(permissionKey, permissions.getProperty(propName));
                    }
                }
            }
        } catch (Exception e) {
            aivRole.put("name", roleName);
            aivRole.put("description", "Error loading permissions");
        }
        return aivRole;
    }


    @Override
    public void setSource(DataSource ds, String deptCode, String traceid) {
        //this.dataSource =ds;
        this.traceid = traceid;
        this.deptCode = deptCode;
    }

    @Override
    public void setApplicationContextAndDatasource(ApplicationContext context) {
//        this.dataSource = (DataSource) context.getBean("dataSource1");
    }

    @Override
    public List<Map<String, Object>> getAllUsers(String s, Map<String, Object> data) {
        try {

            String realm = (data != null && data.containsKey("deptCode")) ? data.get("deptCode").toString() : this.deptCode;
            if (realm == null) {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "getAllUsers called with no realm/deptCode.", this.traceid, "UNKNOWN", null);
                return Collections.emptyList();
            }

            System.out.println("Realm in getAllUsers: " + realm);
            String url = getKeycloakAdminUrl() + "/" + realm + "/users";
            System.out.println("Url in getAllUsers: " + url);
            String response = executeKeycloakGetRequest(url);
            System.out.println("Response in getAllUsers: " + response);

            if (response == null) return Collections.emptyList();

            List<Map<String, Object>> keycloakUsers = objectMapper.readValue(response, MAP_LIST_TYPE_REF);

            List<Map<String, Object>> allUsers = keycloakUsers.stream()
                    .map(keycloakUser -> buildAivUserProfile(keycloakUser, realm))
                    .collect(Collectors.toList());

            System.out.println("All users in getAllUsers: " + allUsers);

            return allUsers;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to get all users", this.traceid, this.deptCode, e);
            return Collections.emptyList();
        }
    }

    @Override
    public List<Map<String, Object>> getAllRoles(String s, Map<String, Object> data) {
        try {
            String realm = (data != null && data.containsKey("deptCode")) ? data.get("deptCode").toString() : this.deptCode;
            if (realm == null) {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "getAllRoles called with no realm/deptCode specified.", this.traceid, "UNKNOWN", null);
                return Collections.emptyList();
            }

            System.out.println("Realm in getAllRoles: " + realm);

            String url = getKeycloakAdminUrl() + "/" + realm + "/roles";
            System.out.println("Url in getAllRoles: " + url);

            String response = executeKeycloakGetRequest(url);
            System.out.println("Response in getAllRoles: " + response);

            List<Map<String, Object>> keycloakRoles = objectMapper.readValue(response, MAP_LIST_TYPE_REF);

            List<Map<String, Object>> allRolesAfterTransform = keycloakRoles.stream()
                    .map(keycloakRole -> transformKeycloakRoleToAivRole(keycloakRole, realm))
                    .collect(Collectors.toList());

            System.out.println("All roles after transforamtion: " + allRolesAfterTransform);

            return allRolesAfterTransform;

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to get all roles", this.traceid, this.deptCode, e);
            return Collections.emptyList();
        }
    }

    @Override
    public List<Map<String, Object>> getAllDepartments(String deptCode, Map<String, Object> data) {

        try {
            String url = getKeycloakAdminUrl();
            String response = executeKeycloakGetRequest(url);
            if (response == null) return Collections.emptyList();

            List<Map<String, Object>> keycloakRealms = objectMapper.readValue(response, MAP_LIST_TYPE_REF);
            return keycloakRealms.stream()
                    .map(realm -> {
                        Map<String, Object> dept = new HashMap<>();
                        dept.put("deptcode", realm.get("realm"));
                        dept.put("deptname", realm.get("displayName") != null ? realm.get("displayName") : realm.get("realm"));
                        dept.put("id", realm.get("id"));
                        return dept;
                    })
                    .collect(Collectors.toList());
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to get all departments (realms)", this.traceid, this.deptCode, e);
            return Collections.emptyList();
        }
    }

    @Override
    public Map<String, Object> authenticate(Map<String, Object> map) {
        try {
            if (isUserExists(map.get("userName").toString(), this.deptCode)) {
                Map<String, Object> authenticatedUser = new HashMap<>();
                authenticatedUser.put("userName", map.get("userName"));
                authenticatedUser.put("department", this.deptCode);
                System.out.println("Authenticate: " + authenticatedUser);
                return authenticatedUser;
            }
            return null;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, KeycloakAuthImpl.class, e.getMessage(), this.traceid, this.deptCode, e);
            return null;
        }
    }

    @Override
    public Map<String, Object> embedAuthenticate(HttpServletRequest req, HttpServletResponse res, Map<String, Object> data) {
        return Map.of();
    }


    @Override
    public boolean isAuthorize(Map<String, Object> headers) {
        String traceid = (!headers.containsKey("traceid") ?
                (!headers.containsKey("userName") ? headers.get("owner").toString() : headers.get("userName").toString())
                : headers.get("traceid").toString());

        String deptCode = headers.containsKey("dc") ? headers.get("dc").toString() : "KEYCLOAK AUTHENTICATION";

        return CommonUtility.isAuthneticated(traceid, deptCode);
    }

    @Override
    public int changePassword(Map<String, Object> user, String deptCode, String traceid) {
        return 0;
    }

    @Override
    public List<Map<String, Object>> selectUsersOfRole(String role, String dc) {
        try {
            String url = getKeycloakAdminUrl() + "/" + dc + "/roles/" + role + "/users";
            System.out.println("Url in selectUsersOfRole: " + url);
            String response = executeKeycloakGetRequest(url);
            if (response != null) {
                return objectMapper.readValue(response, MAP_LIST_TYPE_REF);
            }
            return Collections.emptyList();
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to select users for role: " + role, this.traceid, dc, e);
            return Collections.emptyList();
        }
    }

    @Override
    public List<Map<String, Object>> selectRolesOfUser(String user, String dc) {
        try {

            String userId = getUserId(user, dc);
            if (userId == null) return Collections.emptyList();

            String url = getKeycloakAdminUrl() + "/" + dc + "/users/" + userId + "/role-mappings/realm";
            System.out.println("Url in selectRolesOfUser: " + url);
            String response = executeKeycloakGetRequest(url);
            return response != null ? objectMapper.readValue(response, MAP_LIST_TYPE_REF) : Collections.emptyList();
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to select roles for user: " + user, this.traceid, dc, e);
            return Collections.emptyList();
        }
    }

    @Override
    public boolean isRoleExists(String s, String s1) {
        return true;
    }

    @Override
    public boolean isUserExists(String name, String deptCode) {
        try {
            String adminToken = getAdminToken();
            if (adminToken == null) return false;

            String url = getKeycloakAdminUrl() + "/" + deptCode + "/users?exact=true&username=" + name;
            System.out.println("Url of isUserExists: " + url);
            Map<String, Object> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + adminToken);

            String response = restUtils.getRequest(url, headers, this.traceid);
            List<Map<String, Object>> users = objectMapper.readValue(response, MAP_LIST_TYPE_REF);
            boolean userExistsStatus = users != null && !users.isEmpty();
            System.out.println("User exists status: " + userExistsStatus);
            return userExistsStatus;
        } catch (Exception e) {
            // Log error but treat as user not existing
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Error checking if user exists: " + name, this.traceid, deptCode, e);
            return false;
        }
    }

    @Override
    public Map<String, Object> getUserByName(String userName, String dnm, Map<String, Object> data) {
        try {
            String userId = getUserId(userName, dnm);
            if (userId == null) return null;

            String url = getKeycloakAdminUrl() + "/" + dnm + "/users/" + userId;
            String response = executeKeycloakGetRequest(url);
            if (response == null) return null;

            Map<String, Object> keycloakUser = objectMapper.readValue(response, MAP_TYPE_REF);

            Map<String, Object> userByName = buildAivUserProfile(keycloakUser, dnm);
            System.out.println("User By Name in getUserByName: " + userByName);
            return userByName;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to get user by name: " + userName, this.traceid, dnm, e);
            return null;
        }
    }

    @Override
    public Map<String, Object> getRoleByName(String roleName, String dnm, Map<String, Object> data) {
        try {
            String url = getKeycloakAdminUrl() + "/" + dnm + "/roles/" + roleName;
            System.out.println("Url in getRoleByName: " + url);
            String response = executeKeycloakGetRequest(url);
            if (response != null) {
                return objectMapper.readValue(response, MAP_TYPE_REF);
            }
            return null;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to get role by name: " + roleName, this.traceid, dnm, e);
            return null;
        }
    }

    @Override
    public int CreateEditUser(Map<String, Object> data, String deptCode) {
        try {
            String adminToken = getAdminToken();
            if (adminToken == null) return -1;

            Map<String, Object> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + adminToken);

            List<Map<String, Object>> body = new ArrayList<>();
            Map<String, Object> userPayload = new HashMap<>();
            userPayload.put("username", data.get("userName"));
            userPayload.put("email", data.get("email"));
            userPayload.put("firstName", data.get("firstName"));
            userPayload.put("lastName", data.get("lastName"));
            userPayload.put("enabled", true); // Users should be enabled by default

            if (data.containsKey("password")) {
                Map<String, Object> creds = new HashMap<>();
                creds.put("type", "password");
                creds.put("value", data.get("password"));
                creds.put("temporary", false);
                userPayload.put("credentials", List.of(creds));
            }


            body.add(userPayload);
            System.out.println("Body of CreateEditUser: " + body);

            boolean isEdit = data.containsKey("editFlag") && Boolean.parseBoolean(data.get("editFlag").toString());

            if (isEdit) {
                String userId = getUserId(data.get("userName").toString(), deptCode);
                if (userId == null) return -1;
                String url = getKeycloakAdminUrl() + "/" + deptCode + "/users/" + userId;
                System.out.println("Url in CreateEditUser with userId: " + url);
                restUtils.putRequest(url, headers, body, this.traceid);
            } else {
                String url = getKeycloakAdminUrl() + "/"  + deptCode + "/users";
                System.out.println("Url in CreateEditUser without userId: " + url);
                restUtils.postRequest(url, headers, body, this.traceid);
            }
            return 1; // Success
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to create/edit user", this.traceid, deptCode, e);
            return -1;
        }
    }

    @Override
    public int CreateEditRole(Map<String, Object> data, String deptCode) {

        try {
            String adminToken = getAdminToken();
            if (adminToken == null) return -1;

            Map<String, Object> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + adminToken);

            Map<String, Object> rolePayload = new HashMap<>();
            rolePayload.put("name", data.get("name"));
            rolePayload.put("description", data.get("description"));
            List<Map<String, Object>> body = List.of(rolePayload);
            System.out.println("Body in CreateEditRole: " + body);

            String url = getKeycloakAdminUrl() + deptCode + "/roles";
            System.out.println("Url in CreateEditRole: " + url);
            restUtils.postRequest(url, headers, body, this.traceid);
            return 1;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to create role", this.traceid, deptCode, e);
            return -1;
        }

    }

    @Override
    public int CreateEditDepartment(Map<String, Object> data, String deptCode) {
        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Create/Edit Department (Realm) is not supported via the application API. This must be done in the Keycloak Admin Console.", this.traceid, this.deptCode, null);
        return -1;
    }

    @Override
    public List<Map<String, Object>> getAlldepartmentsWithAdmin(String owner, String deptCode) {

        List<Map<String, Object>> departments = getAllDepartments(deptCode, null);
        List<Map<String, Object>> result = new ArrayList<>();

        for (Map<String, Object> dept : departments) {
            String realmName = dept.get("deptcode").toString();
            String adminUserName = "N/A";
            try {
                String url = getKeycloakAdminUrl() + "/" + realmName + "/roles/realm-admin/users";
                System.out.println("Url in getAlldepartmentsWithAdmin: " + url);
                String response = executeKeycloakGetRequest(url);
                if (response != null) {
                    List<Map<String, Object>> adminUsers = objectMapper.readValue(response, MAP_LIST_TYPE_REF);
                    if (!adminUsers.isEmpty()) {
                        adminUserName = adminUsers.get(0).get("username").toString();
                    }
                }
            } catch (Exception e) {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, this.getClass().getName(), "Could not find admin user for realm: " + realmName, this.traceid, this.deptCode, e);
            }
            dept.put("userName", adminUserName);
            result.add(dept);
        }
        return result;
    }

    @Override
    public int deleteDeptById(String owner, Map<String, Object> deptId) {
        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "deleteDeptById is not supported. Realms must be managed in the Keycloak console.", this.traceid, this.deptCode, null);
        return -1;

    }

//    public void rollBackDepartment(String deptCode) {
//        try {
//            //String fileName = "/com/b/ai_postgresql_delete.sql";
//
//            String fileName = "ai_delete_postgresql_general.sql";
//
//            String content = null;
//            try {
//
//                InputStream inputStream = Files.newInputStream(Paths.get( GetBean.REPOSITORYLOCATION_PATH+"/econfig/"+fileName));
//
//
//                content = IOUtils.toString(inputStream);
//            } catch (IOException e) {
//                AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, KeycloakAuthImpl.class, e.getMessage(), this.traceid, deptCode, e);
//            }
//
//            content = content.replaceAll("XXXXX", deptCode);
//            Resource resource = new ByteArrayResource(content.getBytes());
//
//            ResourceDatabasePopulator databasePopulator = new ResourceDatabasePopulator(resource);
//            databasePopulator.setSeparator("//@");
//            databasePopulator.execute(this.dataSource);
//
//
//        } catch (Exception e) {
//            AuditLoggerUtil.log(AuditLoggerUtil.CORELOGGER, AuditLoggerUtil.ERROR, KeycloakAuthImpl.class, e.getMessage(),
//                    this.traceid, this.deptCode, e);
//        }
//    }

    @Override
    public int deleteUserById(String userName, String deptCode) {
        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, this.getClass().getName(), "Delete User is a disabled function in this implementation.", this.traceid, deptCode, null);
        return -1;
    }

    @Override
    public int deleteRoleById(String roleName, String deptCode) {

        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, this.getClass().getName(), "Delete Role is a disabled function in this implementation.", this.traceid, deptCode, null);
        return -1;

    }

    @Override
    public Map<String, Object> getUserRoleFeatures(String userName, String deptCode) {
        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, this.getClass().getName(), "getUserRoleFeatures is a passthrough method. Logic is in UserInfoServices.", this.traceid, deptCode, null);
        return new HashMap<>();
    }

    @Override
    public int updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode,String traceid) {
        String roleName = userRoleData.get("roleName").toString();
        System.out.println("Role Name in updateUsersForRole: " + roleName);
        Set<String> desiredUsernames = new HashSet<>(Arrays.asList(userRoleData.get("users").toString().split(",")));

        try {
            Map<String, Object> roleObject = getRoleByName(roleName, deptCode, null);
            System.out.println("Role Obj in updateUsersForRole: " + roleObject);
            if (roleObject == null) {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Cannot update users for a non-existent role: " + roleName, traceid, deptCode, null);
                return -1;
            }

            List<Map<String, Object>> currentUsers = selectUsersOfRole(roleName, deptCode);
            System.out.println("Current Usrs in updateUsersForRole: " + currentUsers);
            Set<String> currentUsernames = currentUsers.stream()
                    .map(u -> u.get("username").toString())
                    .collect(Collectors.toSet());

            List<String> usersToAdd = desiredUsernames.stream()
                    .filter(username -> !currentUsernames.contains(username))
                    .collect(Collectors.toList());

            if (usersToAdd.isEmpty()) {
                return 1;
            }

            String authToken = new CommonUtility().getMasterRealmToken(traceid, "master");
            System.out.println("Auth token: " + authToken);
            Map<String, Object> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + authToken);

            for (String username : usersToAdd) {
                String userId = getUserId(username, deptCode);
                if (userId != null) {
                    String url = getKeycloakAdminUrl() + "/" + deptCode + "/users/" + userId + "/role-mappings/realm";
                    restUtils.postRequest(url, headers, List.of(roleObject), traceid);
                } else {
                    AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, this.getClass().getName(), "User '" + username + "' not found. Cannot assign role '" + roleName + "'.", traceid, deptCode, null);
                }
            }
            return 1;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to update users for role: " + roleName, traceid, deptCode, e);
            return -1;
        }
    }

    @Override
    public boolean deptExists(String deptCode, String traceid) {
        try {
            String url = getKeycloakAdminUrl() + "/" + deptCode;
            String response = executeKeycloakGetRequest(url);
            return response != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Map<String, Object> getAuthAfterTimeUser(String userName, String dc, String traceid) {
        try {
            this.traceid = traceid;
            this.deptCode = dc;
            String userId = getUserId(userName, dc);
            if (userId == null) return null;

            String url = getKeycloakAdminUrl() + "/" + dc + "/users/" + userId;
            String response = executeKeycloakGetRequest(url);
            if (response == null) return null;

            Map<String, Object> keycloakUser = objectMapper.readValue(response, MAP_TYPE_REF);
            return buildAivUserProfile(keycloakUser, dc);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Error in getAuthAfterTimeUser: " + e.getMessage(), traceid, dc, e);
            return null;
        }
    }


    @Override
    public String generateEmbedToken(Map<String, Object> data, String deptCode, String traceid) {
        return "";
    }

    @Override
    public int updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
        try {
            String adminToken = getAdminToken();
            if (adminToken == null) return -1;

            String userName = userRoleData.get("userName").toString();
            String userId = getUserId(userName, deptCode);
            if (userId == null) return -1;

            List<Map<String, Object>> allRoles = getAllRoles("", Map.of("deptCode", deptCode));
            System.out.println("All roles in updateRolesForUser: " + allRoles);
            if (allRoles.isEmpty()) return -1;

            List<Map<String, Object>> currentRolesList = selectRolesOfUser(userName, deptCode);
            System.out.println("Current Roles list in updateRolesForUser: " + currentRolesList);
            Set<String> currentRoleNames = currentRolesList.stream().map(r -> r.get("name").toString()).collect(Collectors.toSet());
            System.out.println("Current role names in updateRolesForUser: " + currentRoleNames);

            Set<String> desiredRoleNames = new HashSet<>(Arrays.asList(userRoleData.get("roles").toString().split(",")));

            List<Map<String, Object>> rolesToAdd = allRoles.stream()
                    .filter(r -> desiredRoleNames.contains(r.get("name").toString()) && !currentRoleNames.contains(r.get("name").toString()))
                    .collect(Collectors.toList());

            List<Map<String, Object>> rolesToRemove = currentRolesList.stream()
                    .filter(r -> !desiredRoleNames.contains(r.get("name").toString()))
                    .collect(Collectors.toList());

            Map<String, Object> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + adminToken);
            String url = getKeycloakAdminUrl() + deptCode + "/users/" + userId + "/role-mappings/realm";

            if (!rolesToRemove.isEmpty()) {
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, this.getClass().getName(), "Role removal might require custom DELETE with body", traceid, deptCode, null);
            }
            if (!rolesToAdd.isEmpty()) {
                restUtils.postRequest(url, headers, rolesToAdd, traceid);
            }

            return 1;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), "Failed to update roles for user", traceid, deptCode, e);
            return -1;
        }
    }

}
