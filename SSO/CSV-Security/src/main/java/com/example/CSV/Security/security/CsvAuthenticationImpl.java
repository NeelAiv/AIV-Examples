package com.example.CSV.Security.security;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.IAuthentication;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

@Service
public class CsvAuthenticationImpl implements IAuthentication {

    private static CsvAuthenticationImpl instance;

    public static CsvAuthenticationImpl getInstance() {
        if (instance == null) {
            System.err.println("FATAL: CsvAuthenticationImpl.getInstance() called before AIV framework initialized it!");
        }
        return instance;
    }

    private final JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();

    private ResourceLoader resourceLoader;
    private String usersFilePath;
    private String rolesFilePath;
    private String userRolesFilePath;
    private String userDefaultsPath;

    private static List<Map<String, String>> users;
    private static List<Map<String, String>> roles;
    private static List<Map<String, String>> userRoles;
    private static Properties userDefaults;
    private static final ReadWriteLock lock = new ReentrantReadWriteLock();

    private String traceid = "CSV_AUTH_SYSTEM";
    private String deptCode = "Default";

    public CsvAuthenticationImpl() {
    }

    @Override
    public void setApplicationContextAndDatasource(ApplicationContext context) {
        this.resourceLoader = context;
        Environment environment = context.getEnvironment();

        this.usersFilePath = environment.getProperty("sso.csv.users-file");
        this.rolesFilePath = environment.getProperty("sso.csv.roles-file");
        this.userRolesFilePath = environment.getProperty("sso.csv.user-roles-file");
        this.userDefaultsPath = environment.getProperty("sso.user-defaults-path");

        this.loadDataFromCsv();

        instance = this;
    }

    private void loadDataFromCsv() {
        CsvAuthenticationImpl.users = loadCsvFile(this.usersFilePath);
        CsvAuthenticationImpl.roles = loadCsvFile(this.rolesFilePath);
        CsvAuthenticationImpl.userRoles = loadCsvFile(this.userRolesFilePath);
        CsvAuthenticationImpl.userDefaults = loadPropertiesFile(this.userDefaultsPath);
        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.INFO, "CsvAuthenticationImpl", "CSV data loaded successfully.", traceid, deptCode, null);
    }

    @Override
    public Map<String, Object> authenticate(Map<String, Object> map) {
        String username = ((String) map.get("userName")).trim();
        String password = (String) map.get("password");
        String deptCode = ((String) map.get("deptCode")).trim();

        lock.readLock().lock();
        try {
            if (users == null) {
                System.err.println("AUTHENTICATION FAILED: 'users' list is null. The wrong instance was likely used.");
                return null;
            }
            Optional<Map<String, String>> foundUser = users.stream()
                    .filter(u -> u.get("userName").trim().equals(username) &&
                            u.get("department").trim().equalsIgnoreCase(deptCode))
                    .findFirst();

            if (foundUser.isPresent()) {
                Map<String, String> user = foundUser.get();
                if (user.get("password").trim().equals(password) &&
                        "Active".equalsIgnoreCase(user.get("status").trim())) {

                    Map<String, Object> userDetails = new HashMap<>(user);
                    userDetails.remove("password");

                    return userDetails;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, "CsvAuthenticationImpl", "Failed authentication for user: " + username, traceid, deptCode, null);
        return null;
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
                    CsvAuthenticationImpl.class, e.getMessage(), "AUTHENTICATION",
                    data.get("deptCode").toString(), e);
            return null;
        }
    }

    @Override
    public List<Map<String, Object>> getAllDepartments(String deptCode, Map<String, Object> data) {
        lock.readLock().lock();
        try {
            if (users == null) {
                return Collections.emptyList();
            }
            return users.stream()
                    .map(user -> user.get("department"))
                    .filter(d -> d != null && !d.trim().isEmpty())
                    .distinct()
                    .map(deptName -> {
                        Map<String, Object> deptMap = new HashMap<>();
                        deptMap.put("deptname", deptName);
                        deptMap.put("deptcode", deptName);
                        return deptMap;
                    })
                    .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }

    private List<Map<String, String>> loadCsvFile(String resourcePath) {
        List<Map<String, String>> records = new ArrayList<>();
        if (resourceLoader == null || resourcePath == null) return records;
        try (InputStream inputStream = resourceLoader.getResource(resourcePath).getInputStream();
             CSVReader reader = new CSVReader(new InputStreamReader(inputStream))) {
            List<String[]> allRows = reader.readAll();
            if (allRows.size() < 2) return records;
            String[] headers = allRows.get(0);
            for (int i = 1; i < allRows.size(); i++) {
                Map<String, String> record = new HashMap<>();
                String[] currentRow = allRows.get(i);
                for (int j = 0; j < headers.length; j++) {
                    String value = (j < currentRow.length) ? currentRow[j] : "";
                    record.put(headers[j], value);
                }
                records.add(record);
            }
        } catch (IOException | CsvException e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, "CsvAuthenticationImpl", "Failed to load CSV resource: " + resourcePath, traceid, deptCode, e);
        }
        return records;
    }

    private Properties loadPropertiesFile(String resourcePath) {
        Properties properties = new Properties();
        if (resourceLoader == null || resourcePath == null) return properties;
        try (InputStream inputStream = resourceLoader.getResource(resourcePath).getInputStream()) {
            properties.load(inputStream);
        } catch (IOException e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, "CsvAuthenticationImpl", "Failed to load properties resource: " + resourcePath, traceid, deptCode, e);
        }
        return properties;
    }

    @Override
    public Map<String, Object> getAuthAfterTimeUser(String userName, String dc, String traceid) {
        Map<String, Object> userFeatures = getUserRoleFeatures(userName, dc);

        if (userFeatures == null || userFeatures.isEmpty()) {
            return null;
        }

        List<String> assignedRoles = (userRoles == null) ? Collections.emptyList() : userRoles.stream()
                .filter(ur -> userName.equalsIgnoreCase(ur.get("userName")))
                .map(ur -> ur.get("roleName"))
                .collect(Collectors.toList());

        Map<String, Object> finalPayload = new HashMap<>();

        finalPayload.put("adhocOption", userFeatures.getOrDefault("adhocOption", "0"));
        finalPayload.put("adminOption", userFeatures.getOrDefault("adminOption", "0"));
        finalPayload.put("alertsOption", userFeatures.getOrDefault("alertsOption", "0"));
        finalPayload.put("annotationOption", userFeatures.getOrDefault("annotationOption", "0"));
        finalPayload.put("backupUserId", userFeatures.getOrDefault("backupUserId", ""));
        finalPayload.put("dashboardOption", userFeatures.getOrDefault("dashboardOption", "0"));
        finalPayload.put("datasetOption", userFeatures.getOrDefault("datasetOption", "0"));
        finalPayload.put("default_dashboard", userFeatures.getOrDefault("default_dashboard", ""));
        finalPayload.put("department", userFeatures.getOrDefault("department", "Default"));
        finalPayload.put("email", userFeatures.getOrDefault("email", ""));
        finalPayload.put("firstName", userFeatures.getOrDefault("firstName", ""));
        finalPayload.put("homeFolder", userFeatures.getOrDefault("homeFolder", "/" + userName));
        finalPayload.put("landing_page", userFeatures.getOrDefault("landing_page", "Documents/Reports"));
        finalPayload.put("lastName", userFeatures.getOrDefault("lastName", ""));
        finalPayload.put("locale", userFeatures.getOrDefault("locale", "en"));
        finalPayload.put("managerUserId", userFeatures.getOrDefault("managerUserId", "0"));
        finalPayload.put("mappingOption", userFeatures.getOrDefault("mappingOption", "0"));
        finalPayload.put("mergeReportOption", userFeatures.getOrDefault("mergeReportOption", "0"));
        finalPayload.put("messageOption", userFeatures.getOrDefault("messageOption", "0"));
        finalPayload.put("notification", userFeatures.getOrDefault("notification", "0"));
        finalPayload.put("notificationOption", userFeatures.getOrDefault("notificationOption", "0"));
        finalPayload.put("parameterOption", userFeatures.getOrDefault("parameterOption", "0"));
        finalPayload.put("quickRunOption", userFeatures.getOrDefault("quickRunOption", "0"));
        finalPayload.put("reportOption", userFeatures.getOrDefault("reportOption", "0"));
        finalPayload.put("requestOption", userFeatures.getOrDefault("requestOption", "0"));
        finalPayload.put("resourceOption", userFeatures.getOrDefault("resourceOption", "0"));
        finalPayload.put("scheduleOption", userFeatures.getOrDefault("scheduleOption", "0"));
        finalPayload.put("webhookOption", userFeatures.getOrDefault("webhookOption", "0"));
        finalPayload.put("showimage", userFeatures.getOrDefault("showimage", "1"));
        finalPayload.put("showname", userFeatures.getOrDefault("showname", "1"));
        finalPayload.put("status", userFeatures.getOrDefault("status", "Active"));
        finalPayload.put("theme", userFeatures.getOrDefault("theme", "Default"));
        finalPayload.put("timezone", userFeatures.getOrDefault("timezone", "SYSTEM"));
        finalPayload.put("userName", userName);
        finalPayload.put("userType", userFeatures.getOrDefault("userType", "INT"));
        finalPayload.put("roles", String.join(",", assignedRoles));
        finalPayload.put("owner", userName);

        return finalPayload;
    }

    @Override
    public Map<String, Object> getUserRoleFeatures(String userName, String deptCode) {
        lock.readLock().lock();
        try {

            if (userName == null || deptCode == null) {
                return Collections.emptyMap();
            }

            Map<String, Object> finalFeatures = new HashMap<>();
            if (users == null) return finalFeatures;

            final String trimmedUserName = userName.trim();
            final String trimmedDeptCode = deptCode.trim();

            Optional<Map<String, String>> userOpt = users.stream()
                    .filter(u -> u.get("userName").trim().equalsIgnoreCase(trimmedUserName) &&
                            u.get("department").trim().equalsIgnoreCase(trimmedDeptCode))
                    .findFirst();

            if (userOpt.isEmpty()) return finalFeatures;
            finalFeatures.putAll(userOpt.get());

            List<String> assignedRoleNames = userRoles.stream()
                    .filter(ur -> ur.get("userName").trim().equalsIgnoreCase(trimmedUserName))
                    .map(ur -> ur.get("roleName"))
                    .collect(Collectors.toList());

            roles.stream()
                    .filter(r -> assignedRoleNames.contains(r.get("name").trim()))
                    .forEach(role -> {
                        role.forEach((key, value) -> {
                            if (key.endsWith("Option")) {
                                int currentLevel = Integer.parseInt(finalFeatures.getOrDefault(key, "0").toString());
                                int roleLevel = Integer.parseInt(value);
                                if (roleLevel > currentLevel) {
                                    finalFeatures.put(key, String.valueOf(roleLevel));
                                }
                            }
                        });
                    });

            finalFeatures.remove("password");
            return finalFeatures;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<Map<String, Object>> getAlldepartmentsWithAdmin(String owner, String deptCode) {
        lock.readLock().lock();
        try {
            if (users == null || userRoles == null) {
                return Collections.emptyList();
            }
            List<String> departmentNames = users.stream()
                    .map(u -> u.get("department"))
                    .filter(d -> d != null && !d.trim().isEmpty())
                    .distinct()
                    .collect(Collectors.toList());

            Set<String> adminUserNames = userRoles.stream()
                    .filter(ur -> "Administrator".equalsIgnoreCase(ur.get("roleName")))
                    .map(ur -> ur.get("userName"))
                    .collect(Collectors.toSet());

            return departmentNames.stream()
                    .map(deptName -> {
                        Optional<Map<String, String>> adminUserRecordOpt = users.stream()
                                .filter(u -> deptName.equalsIgnoreCase(u.get("department")) && adminUserNames.contains(u.get("userName")))
                                .findFirst();

                        Map<String, Object> result = new HashMap<>();
                        result.put("deptCode", deptName);
                        result.put("deptName", deptName);

                        if (adminUserRecordOpt.isPresent()) {
                            result.putAll(adminUserRecordOpt.get());
                        } else {
                            result.put("userName", "");
                        }
                        return result;
                    })
                    .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public int CreateEditUser(Map<String, Object> data, String deptCode) {
        return -1;
    }

    @Override
    public boolean isUserExists(String name, String deptCode) {
        lock.readLock().lock();
        try {
            if (users == null) return false;
            return users.stream().anyMatch(u -> u.get("userName").equalsIgnoreCase(name) && u.get("department").equalsIgnoreCase(deptCode));
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<Map<String, Object>> getAllUsers(String deptCode, Map<String, Object> map) {
        if (users == null) return Collections.emptyList();
        return users.stream().<Map<String, Object>>map(HashMap::new).collect(Collectors.toList());
    }

    @Override
    public List<Map<String, Object>> getAllRoles(String deptCode, Map<String, Object> map) {
        if (roles == null) return Collections.emptyList();
        return roles.stream().<Map<String, Object>>map(HashMap::new).collect(Collectors.toList());
    }

    @Override
    public Map<String, Object> getUserByName(String userName, String deptCode, Map<String, Object> map) {
        if (users == null) return null;
        return users.stream()
                .filter(u -> u.get("userName").equalsIgnoreCase(userName) && u.get("department").equalsIgnoreCase(deptCode))
                .findFirst()
                .<Map<String, Object>>map(HashMap::new)
                .orElse(null);
    }

    @Override
    public Map<String, Object> getRoleByName(String roleName, String deptCode, Map<String, Object> map) {
        if (roles == null) return null;
        return roles.stream()
                .filter(r -> r.get("name").equalsIgnoreCase(roleName) && r.get("department").equalsIgnoreCase(deptCode))
                .findFirst()
                .<Map<String, Object>>map(HashMap::new)
                .orElse(null);
    }

    @Override
    public boolean isAuthorize(Map<String, Object> headers) {
        try {

            String token = (String) headers.get("x-xsrftoken");

            if (token == null || token.trim().isEmpty()) {
                token = (String) headers.get("token");
                AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.WARN, "CsvAuthenticationImpl", "Authorization failed: Missing token.", traceid, deptCode, null);
                return false;
            }
            if (token == null || token.trim().isEmpty()) {
                return false;
            }


            String deptCode = (String) headers.get("dc");
            String traceId = (String) headers.get("traceid");

            if (token == null || token.trim().isEmpty()) {
                return false;
            }

            boolean isAuthenicated = isAuthneticated(token, traceId, deptCode);

            return isAuthenicated;
        } catch (Exception e){
            e.printStackTrace();
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR,
                    CsvAuthenticationImpl.class, e.getMessage(), "AUTHENTICATION",
                    headers.get("dc") != null ? headers.get("dc").toString() : "unknown", e);
            return false;
        }
    }

    public static Boolean isAuthneticated(String token,String deptCode,String traceid) {
        try {

            return new JwtTokenUtil().validateToken(token);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, CsvAuthenticationImpl.class, e.getMessage(),
                    traceid,deptCode, e);
            return false;
        }
    }

    @Override public void setSource(DataSource dataSource, String deptCode, String traceid) { this.deptCode = deptCode; this.traceid = traceid; }
    @Override public int changePassword(Map<String, Object> user, String deptCode, String traceid) { return -1; }
    @Override public List<Map<String, Object>> selectUsersOfRole(String role, String deptCode) { return new ArrayList<>(); }
    @Override public List<Map<String, Object>> selectRolesOfUser(String user, String deptCode) { return new ArrayList<>(); }
    @Override public boolean isRoleExists(String name, String deptCode) { if (roles == null) return false; return roles.stream().anyMatch(r -> r.get("name").equalsIgnoreCase(name)); }
    @Override public int CreateEditRole(Map<String, Object> data, String deptCode) { return -1; }
    @Override public int CreateEditDepartment(Map<String, Object> data, String deptCode) { return -1; }
    @Override public int deleteDeptById(String owner, Map<String, Object> deptId) { return -1; }
    @Override public int deleteUserById(String userName, String deptCode) { return -1; }
    @Override public int deleteRoleById(String roleName, String deptCode) { return -1; }
    @Override public int updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) { return -1; }
    @Override public int updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) { return -1; }
    @Override public boolean deptExists(String deptCode, String traceid) { return true; }
    @Override public String generateEmbedToken(Map<String, Object> data, String deptCode, String traceid) { return "dummy-token"; }
}