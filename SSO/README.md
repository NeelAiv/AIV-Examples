# Spring Boot Security Application

## Introduction

This application is a robust and customizable security solution for Spring Boot applications. It provides a flexible framework for Single Sign-On (SSO) and can be adapted to various authentication and authorization scenarios. The core of this application is the `IAuthentication` interface, which allows you to integrate your own authentication logic seamlessly.

### Key Features

*   **SSO (Single Sign-On):** Provides a centralized authentication service for multiple applications.
*   **Customizable Authentication:** The `IAuthentication` interface allows you to implement your own authentication logic, enabling integration with various identity providers and user stores.
*   **Role-Based Access Control (RBAC):** Manage user permissions and access levels through a flexible role-based system.
*   **JWT Support:** The application uses JSON Web Tokens (JWT) for secure communication and session management.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Java 17 or higher**
- **Maven 3.2 or higher**
- **PostgreSQL database**

### Required JARs

Download the required JAR files from our repository:
[Additional JARs](https://github.com/aiv-code/docker-aiv/tree/main/config/Additional%20Jars)

These JARs contain essential dependencies for the security framework and should be added to your Maven local repository or classpath before building the project.

## Building the Project

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    ```

2.  **Navigate to the project directory:**

    ```bash
    cd aiaivsecurity
    ```

3.  **Build the project using Maven:**

    ```bash
    mvn clean install -Dmaven.repo.local=D:\Parth\maven\.m2\repository
    ```

    This command will build the project and create a JAR file in the `target` directory.

### Running the Application

1.  **Configure the database:**

    Open the `src/main/resources/application.properties` file and update the following properties with your database connection details:

    ```properties
    spring.datasource1.url=jdbc:postgresql://localhost:5432/your-database
    spring.datasource1.username=your-username
    spring.datasource1.password=your-password
    spring.datasource1.driver-class-name=org.postgresql.Driver
    ```


## Configuration

The application is configured through the `src/main/resources/application.properties` and `src/main/resources/user_Default.properties` files.

### `application.properties`

This file contains the primary configuration for the application, including the database connection details.

```properties
# Datasource settings
spring.datasource.initialize=true
spring.jmx.enabled=false

spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.url=jdbc:postgresql://localhost:5432/postgres?currentSchema=security
spring.datasource.username=postgres
spring.datasource.password=ROOT
spring.datasource.separator=;
spring.jackson.serialization.WRITE_DATES_AS_TIMESTAMPS=false
spring.jackson.time-zone=UTC

app.aiv-internalToken= ActiveIntelligence
```

**Database Configuration**

*   `spring.datasource.url`: The JDBC URL of your PostgreSQL database.
*   `spring.datasource.username`: The username for your database.
*   `spring.datasource.password`: The password for your database.

**Other Properties**

*   `app.aiv-internalToken`: A secret token used for internal communication.

### `user_Default.properties`

This file defines the Default permissions and settings for new users. The properties are prefixed with `Admin_` for Admin users and `demo_` for regular users.

```properties
Admin_adhocOption=2
Admin_AdminOption=2
Admin_alertsOption=2
Admin_annotationOption=2
Admin_dashboardOption=2
Admin_datasetOption=2
Admin_mappingOption=2
Admin_mergeReportOption=2
Admin_messageOption=2
Admin_notificationOption=2
Admin_parameterOption=2
Admin_quickRunOption=2
Admin_reportOption=2
Admin_requestOption=2
Admin_resourceOption=2
Admin_scheduleOption=2
Admin_userType=INT
demo_adhocOption=2
demo_AdminOption=0
demo_alertsOption=2
demo_annotationOption=2
demo_dashboardOption=2
demo_datasetOption=2
demo_mappingOption=2
demo_mergeReportOption=2
demo_messageOption=2
demo_notificationOption=2
demo_parameterOption=2
demo_quickRunOption=2
demo_reportOption=2
demo_requestOption=2
demo_resourceOption=2
demo_scheduleOption=2
demo_userType=INT
```

Each property corresponds to a specific feature or permission in the application. The value of the property determines the level of access:

*   `0`: No access
*   `1`: Read-only access
*   `2`: Full access

## Authentication

The application's security is primarily handled by a custom `AuthenticationFilter` that intercepts incoming requests. This filter leverages the `IAuthentication` interface to perform user authentication.

### `IAuthentication` Interface

The `IAuthentication` interface is the core component for customizing the authentication process. You can implement this interface to integrate your existing authentication system (e.g., LDAP, OAuth2, custom database).

<details>
<summary><strong>Click</strong> to view <strong><code>IAuthentication</code></strong> interface</summary>

```java
package com.aivhub.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

public interface IAuthentication {

    void setApplicationContextAndDatasource(ApplicationContext context);

    void setSource(DataSource dataSource, String deptCode, String traceid);

    List<Map<String, Object>> getAllUsers(String deptCode, Map<String, Object> map);

    List<Map<String, Object>> getAllRoles(String deptCode, Map<String, Object> map);

    List<Map<String, Object>> getAllDepartments(String deptCode, Map<String, Object> data);

    Map<String, Object> authenticate(Map<String, Object> map);

    Map<String, Object> embedAuthenticate(HttpServletRequest req, HttpServletResponse res, Map<String, Object> map);

    boolean isAuthorize(Map<String, Object> headers);

    int changePassword(Map<String, Object> user, String deptCode, String traceid);

    List<Map<String, Object>> selectUsersOfRole(String role, String deptCode);

    List<Map<String, Object>> selectRolesOfUser(String user, String deptCode);

    boolean isRoleExists(String name, String deptCode);

    boolean isUserExists(String name, String deptCode);

    Map<String, Object> getUserByName(String userName, String deptCode, Map<String, Object> map);

    Map<String, Object> getRoleByName(String roleName, String deptCode, Map<String, Object> map);

    int CreateEditUser(Map<String, Object> data, String deptCode);

    int CreateEditRole(Map<String, Object> data, String deptCode);

    int CreateEditDepartment(Map<String, Object> data, String deptCode);

    List<Map<String, Object>> getAlldepartmentsWithAdmin(String owner, String deptCode);

    int deleteDeptById(String owner, Map<String, Object> deptId);

    int deleteUserById(String userName, String deptCode);

    int deleteRoleById(String roleName, String deptCode);

    Map<String, Object> getUserRoleFeatures(String userName, String deptCode);

    int updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid);

    int updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid);

    boolean deptExists(String deptCode, String traceid);

    Map<String, Object> getAuthAfterTimeUser(String userName, String dc, String traceid);

    String generateEmbedToken(Map<String, Object> data, String deptCode, String traceid);
}
```
</details>

### Implementing `IAuthentication`

To provide your own authentication logic, create a new class that implements the `IAuthentication` interface. This allows you to integrate with various identity providers, custom user stores, or existing authentication mechanisms.

<details>
<summary><strong>Click</strong> to view implementation of <strong><code>IAuthentication</code></strong> interface</summary>

```java
package com.yourcompany.security;

import com.aivhub.security.IAuthentication;
import com.aivhub.security.User; // Assuming User class is available in aivhub.security
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Date; // For Date object in getAuthAfterTimeUser

public class CustomAuthenticationImpl implements IAuthentication {

    private DataSource dataSource;
    private String deptCode;
    private String traceid;
    private ApplicationContext applicationContext;

    //deptCode: Department code.
    //traceid: Id to trace whole process

    @Override
    public void setApplicationContextAndDatasource(ApplicationContext context) {
        this.applicationContext = context;
        // You might retrieve your DataSource here if it's a Spring Bean
        // this.dataSource = (DataSource) context.getBean("yourCustomDataSourceBean");
    }

    @Override
    public void setSource(DataSource dataSource, String deptCode, String traceid) {
        this.dataSource = dataSource; // This dataSource is typically provided by the framework
        this.deptCode = deptCode;
        this.traceid = traceid;
    }

    /**
     * Authenticates a user based on the provided credentials.
     * This is the primary method to implement for custom authentication.
     *
     * @param map A map containing authentication details, typically including "userName", "password", "deptCode", and "salt".
     * @return A Map containing user details if authentication is successful, or null otherwise.
     *         The returned map should at least contain "userName" and can include other user attributes.
     * 
     * 
     */

    
    //This method will be automatically called if we are using AIV application login page else need to be called via  Filter (request interpretation ).  

    @Override
    public Map<String, Object> authenticate(Map<String, Object> map) {
        String username = (String) map.get("userName");
        String password = (String) map.get("password");
        String departmentCode = (String) map.get("deptCode");
        String salt = (String) map.get("salt");

        // --- YOUR CUSTOM AUTHENTICATION LOGIC HERE ---
        // This example demonstrates authentication against a simple in-memory store.
        // In a real-world scenario, you would interact with a database, LDAP, or an external identity provider.

        // Example: Authenticating against a hardcoded user
        if ("customuser".equals(username) && "custompass".equals(password) && "customdept".equals(departmentCode)) {
            Map<String, Object> userDetails = new HashMap<>();
            userDetails.put("userName", username);
            userDetails.put("deptCode", departmentCode);
            // Add other relevant user details that your application might need
            return userDetails;
        }

        // Example: Authenticating against a database (conceptual)
        /*
        try {
            // Assuming you have a UserService or direct JDBC access
            // You would typically hash the provided password with the salt and compare it to a stored hash.
            // String hashedPassword = hashPassword(password, salt);
            // User user = userService.findByUsernameAndHashedPassword(username, hashedPassword);

            // For demonstration, let's assume a successful lookup
            if ("dbuser".equals(username) && "dbpass".equals(password)) { // Replace with actual database lookup and password verification
                Map<String, Object> userDetails = new HashMap<>();
                userDetails.put("userName", username);
                userDetails.put("department", departmentCode);
                return userDetails;
            }
        } catch (Exception e) {
            // Handle exception
        }
        */

        // Example: Authenticating against an external OAuth2 provider (conceptual)
        /*
        try {
            // Make an API call to your OAuth2 provider's token endpoint
            // Exchange credentials for an access token
            // If successful, retrieve user info from the OAuth2 provider's userinfo endpoint
            // Map<String, Object> userDetails = oauth2Service.authenticate(username, password);
            // return userDetails;
        } catch (Exception e) {
            // Handle exception
        }
        */

        return null; // Authentication failed
    }

    /**
     * Handles authentication for embedded scenarios, typically involving JWT tokens or other pre-authenticated mechanisms.
     * This method is useful when a token is provided directly (e.g., from another trusted service) instead of username/password.
     *
     * @param req The HttpServletRequest.
     * @param res The HttpServletResponse.
     * @param map A map containing embedded authentication details, e.g., "userName", "token", "keyInfo".
     * @return A Map containing user details if authentication is successful, or null otherwise.
     */
    @Override
    public Map<String, Object> embedAuthenticate(HttpServletRequest req, HttpServletResponse res, Map<String, Object> map) {
        String username = (String) map.get("userName");
        String token = (String) map.get("token");
        String keyInfo = (String) map.get("keyInfo"); // Additional info for token validation

        // --- YOUR CUSTOM EMBEDDED AUTHENTICATION LOGIC HERE ---
        // This typically involves validating the provided token.
        // You might use a JWT library to parse and verify the token's signature and claims.

        // Example: Validating a simple pre-shared token (for demonstration)
        if ("embeddeduser".equals(username) && "PRE_SHARED_SECRET_TOKEN".equals(token)) {
            Map<String, Object> userDetails = new HashMap<>();
            userDetails.put("userName", username);
            userDetails.put("deptCode", departmentCode);
            // Add other relevant user details
            return userDetails;
        }

        // Example: Validating a JWT (conceptual)
        /*
        try {
            // Assuming you have a JwtTokenUtil or similar service
            // boolean isValid = jwtTokenUtil.validateToken(token, keyInfo);
            // if (isValid) {
            //     String extractedUsername = jwtTokenUtil.getUsernameFromToken(token);
            //     // Retrieve full user details based on extractedUsername
            //     Map<String, Object> userDetails = getUserDetailsFromDatabase(extractedUsername);
            //     return userDetails;
            // }
        } catch (Exception e) {
            // Handle exception
        }
        */

        return null; // Embedded authentication failed
    }

    /**
     * Checks if a user is authorized based on provided headers (e.g., containing a valid JWT).
     * This method is typically called after successful authentication to determine if the authenticated user
     * has the necessary permissions for the requested action or resource.
     *
     * @param headers A map containing request headers, typically including "x-xsrftoken" (which might be a JWT),
     *                "dc" (department code), and "traceid".
     * @return true if authorized, false otherwise.
     */
    @Override
    public boolean isAuthorize(Map<String, Object> headers) {
        String jwtToken = (String) headers.get("x-xsrftoken");
        String departmentCode = (String) headers.get("dc");
        String traceId = (String) headers.get("traceid");

        // --- YOUR CUSTOM AUTHORIZATION LOGIC HERE ---
        // This example demonstrates a basic JWT validation and a conceptual role check.
        // In a real application, you would parse the JWT, extract user roles/permissions,
        // and compare them against the required permissions for the current operation.

        // Example: Basic JWT validation (conceptual, assuming JwtTokenUtil is available)
        /*
        try {
            // Assuming JwtTokenUtil.validateToken checks signature and expiration
            boolean isValidToken = new JwtTokenUtil().validateToken(jwtToken);
            if (!isValidToken) {
                System.err.println("Authorization failed: Invalid or expired JWT.");
                return false;
            }

            // Extract username or roles from the JWT claims
            // String username = new JwtTokenUtil().getUsernameFromToken(jwtToken);
            // List<String> userRoles = new JwtTokenUtil().getRolesFromToken(jwtToken);

            // Example: Check if the user has a specific role (e.g., "Admin")
            // if (userRoles.contains("Admin")) {
            //     return true;
            // }

            // Example: Check if the user is authorized for a specific department
            // if (userBelongsToDepartment(username, departmentCode)) {
            //     return true;
            // }

        } catch (Exception e) {
            System.err.println("Authorization error: " + e.getMessage());
            return false;
        }
        */

        // For demonstration, let's assume any valid token grants authorization
        // In a real scenario, you'd have more complex authorization rules.
        if (jwtToken != null && !jwtToken.isEmpty()) {
            // Placeholder for actual token validation and authorization logic
            return true;
        }

        return false; // Authorization failed
    }

    /**
     * Changes a user's password.
     * This method should handle the process of verifying the old password, hashing the new password,
     * and updating it in the user store.
     *
     * @param user A map containing user details, including "userName", "oldPassword", "password" (new password),
     *             and "salt".
     * @param deptCode The department code.
     * @param traceid The trace ID for logging.
     * @return 1 on success, 0 on incorrect old password, -1 on error.
     */
    @Override
    public int changePassword(Map<String, Object> user, String deptCode, String traceid) {
        String username = (String) user.get("userName");
        String oldPassword = (String) user.get("oldPassword");
        String newPassword = (String) user.get("password");
        String salt = (String) user.get("salt");

        // --- YOUR CUSTOM PASSWORD CHANGE LOGIC HERE ---
        // This example outlines the typical steps involved.

        try {
            // 1. Retrieve the user's current hashed password and salt from your user store.
            //    Map<String, Object> storedUserDetails = getUserDetailsFromDatabase(username);
            //    String storedHashedPassword = (String) storedUserDetails.get("password");
            //    String storedSalt = (String) storedUserDetails.get("salt");

            // 2. Hash the provided old password using the stored salt and compare it with the stored hashed password.
            //    String hashedOldPassword = hashPassword(oldPassword, storedSalt);
            //    if (!hashedOldPassword.equals(storedHashedPassword)) {
            //        System.err.println("Change password failed for " + username + ": Incorrect old password.");
            //        return 0; // Incorrect old password
            //    }

            // For demonstration, assume old password is correct if it matches a hardcoded value
            if (!"oldpass".equals(oldPassword)) { // Replace with actual old password verification
                System.err.println("Change password failed for " + username + ": Incorrect old password.");
                return 0; // Incorrect old password
            }

            // 3. Hash the new password using the provided salt (or a newly generated one).
            //    String hashedNewPassword = hashPassword(newPassword, salt);

            // For demonstration, a simple encryption (replace with robust hashing)
            String encryptedNewPassword = "encrypted_" + newPassword; // Replace with actual hashing/encryption

            // 4. Update the user's password in your user store.
            //    updateUserPasswordInDatabase(username, encryptedNewPassword);

            System.out.println("Password successfully changed for " + username);
            return 1; // Success

        } catch (Exception e) {
            System.err.println("Error changing password for " + username + ": " + e.getMessage());
            return -1; // Error
        }
    }

    /**
     * Retrieves a list of all users for a given department.
     * This method should query your user store (e.g., database) and return a list of user details.
     *
     * @param deptCode The department code to filter users by.
     * @param map Additional parameters (e.g., "owner" if filtering by a specific owner).
     * @return A list of maps, where each map represents a user. Each user map should contain at least "userName",
     *         and can include other relevant user attributes like "firstName", "lastName", "email", etc.
     */
    @Override
    public List<Map<String, Object>> getAllUsers(String deptCode, Map<String, Object> map) {
        List<Map<String, Object>> users = new ArrayList<>();

        // --- YOUR CUSTOM LOGIC TO FETCH ALL USERS HERE ---
        // Example: Fetching from a database (conceptual)
        /*
        try {
            // Using JDBC or an ORM to query the ai_user table
            // String sql = "SELECT userName, firstName, lastName, email FROM ai_user WHERE department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, deptCode);
            // ResultSet rs = ps.executeQuery();
            // while (rs.next()) {
            //     Map<String, Object> user = new HashMap<>();
            //     user.put("userName", rs.getString("userName"));
            //     user.put("firstName", rs.getString("firstName"));
            //     user.put("lastName", rs.getString("lastName"));
            //     user.put("email", rs.getString("email"));
            //     users.add(user);
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching all users: " + e.getMessage());
        }
        */

        // For demonstration, return some dummy users
        if ("Default".equals(deptCode)) {
            Map<String, Object> user1 = new HashMap<>();
            user1.put("id", 1);
            user1.put("firstName", "Admin");
            user1.put("lastName", "");
            user1.put("userName", " Admin ");
            user1.put("status", "Active");
            user1.put("userType", "INT");
            user1.put("email", "Admin@aivhub.com");
            user1.put("homeFolder", "/Admin");
            user1.put("backupUserId", "1");
            user1.put("managerUserId", null);
            user1.put("default_dashboard", null);
            user1.put("landing_page", "Documents/Reports");
            user1.put("locale", "en");
            user1.put("timezone", "SYSTEM");
            user1.put("theme", "Default");
            user1.put("notification", "0");
            user1.put("department", "Default");
            user1.put("showname", "1");
            user1.put("showimage", "1");
            user1.put("dashboardOption", "0");
            user1.put("alertsOption", "0");
            user1.put("reportOption", "1");
            user1.put("mergeReportOption", "0");
            user1.put("adhocOption", "2");
            user1.put("resourceOption", "0");
            user1.put("quickRunOption", "0");
            user1.put("mappingOption", "0");
            user1.put("messageOption", "0");
            user1.put("datasetOption", "0");
            user1.put("parameterOption", "0");
            user1.put("annotationOption", "0");
            user1.put("notificationOption", "2");
            user1.put("requestOption", "0");
            user1.put("AdminOption", "1");
            user1.put("scheduleOption", "0");
            user1.put("webhookOption", "0");
            users.add(user1);
        }

        return users;
    }

    /**
     * Retrieves a list of all roles for a given department.
     * This method should query your role store (e.g., database) and return a list of role details.
     *
     * @param deptCode The department code to filter roles by.
     * @param map Additional parameters.
     * @return A list of maps, where each map represents a role. Each role map should contain at least "name",
     *         and can include other relevant role attributes like "description", "email", etc.
     */
    @Override
    public List<Map<String, Object>> getAllRoles(String deptCode, Map<String, Object> map) {
        List<Map<String, Object>> roles = new ArrayList<>();

        // --- YOUR CUSTOM LOGIC TO FETCH ALL ROLES HERE ---
        // Example: Fetching from a database (conceptual)
        /*
        try {
            // String sql = "SELECT name, description FROM ai_role WHERE department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, deptCode);
            // ResultSet rs = ps.executeQuery();
            // while (rs.next()) {
            //     Map<String, Object> role = new HashMap<>();
            //     role.put("name", rs.getString("name"));
            //     role.put("description", rs.getString("description"));
            //     roles.add(role);
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching all roles: " + e.getMessage());
        }
        */

        // For demonstration, return some dummy roles
        if ("Default".equals(deptCode)) {
            Map<String, Object> role1 = new HashMap<>();
            role1.put("id", 1);
            role1.put("name", "Administrator");
            role1.put("email", "Admin@activeintelligence.co.uk");
            role1.put("description", "Administrator Role");
            role1.put("dashboardOption", "2");
            role1.put("alertsOption", "2");
            role1.put("reportOption", "2");
            role1.put("mergeReportOption", "2");
            role1.put("adhocOption", "2");
            role1.put("resourceOption", "2");
            role1.put("quickRunOption", "2");
            role1.put("mappingOption", "2");
            role1.put("messageOption", "2");
            role1.put("datasetOption", "2");
            role1.put("parameterOption", "2");
            role1.put("annotationOption", "2");
            role1.put("notificationOption", "2");
            role1.put("requestOption", "2");
            role1.put("AdminOption", "2");
            role1.put("scheduleOption", "2");
            role1.put("webhookOption", "0");
            role1.put("department", "Default");
            roles.add(role1);
        }

        return roles;
    }

    /**
     * Retrieves a list of all departments.
     * This method should query your department store (e.g., database) and return a list of department details.
     *
     * @param deptCode The department code (can be ignored if fetching all departments).
     * @param data Additional parameters.
     * @return A list of maps, where each map represents a department. Each department map should contain at least "deptcode" and "deptname".
     */
    @Override
    public List<Map<String, Object>> getAllDepartments(String deptCode, Map<String, Object> data) {
        List<Map<String, Object>> departments = new ArrayList<>();

        // --- YOUR CUSTOM LOGIC TO FETCH ALL DEPARTMENTS HERE ---
        // Example: Fetching from a database (conceptual)
        /*
        try {
            // String sql = "SELECT deptcode, deptname FROM ai_department";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, deptCode);
            // ResultSet rs = ps.executeQuery();
            // while (rs.next()) {
            //     Map<String, Object> department = new HashMap<>();
            //     department.put("deptcode", rs.getString("deptcode"));
            //     department.put("deptname", rs.getString("deptname"));
            //     departments.add(department);
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching all departments: " + e.getMessage());
        }
        */

        // For demonstration, return some dummy departments
        Map<String, Object> dept1 = new HashMap<>();
        dept1.put("id", 1);
        dept1.put("deptName", "Default");
        dept1.put("deptCode", "Default");
        dept1.put("userName", "Admin@gmail.com");
        departments.add(dept1);

        return departments;
    }

    /**
     * Selects users belonging to a specific role.
     * This method should query your user and role stores to find users associated with the given role.
     *
     * @param role The role name to search for.
     * @param deptCode The department code.
     * @return A list of maps, where each map represents a user in the specified role. Each user map should contain at least "userName".
     */
    @Override
    public List<Map<String, Object>> selectUsersOfRole(String role, String deptCode) {
        List<Map<String, Object>> usersInRole = new ArrayList<>();

        // --- YOUR CUSTOM LOGIC TO FETCH USERS BY ROLE HERE ---
        // Example: Fetching from a database (conceptual, assuming ai_user_role table)
        /*
        try {
            // String sql = "SELECT u.userName, u.firstName, u.lastName FROM ai_user u JOIN ai_user_role ur ON u.userName = ur.userName WHERE ur.roleName = ? AND u.department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, role);
            // ps.setString(2, deptCode);
            // ResultSet rs = ps.executeQuery();
            // while (rs.next()) {
            //     Map<String, Object> user = new HashMap<>();
            //     user.put("userName", rs.getString("userName"));
            //     user.put("firstName", rs.getString("firstName"));
            //     user.put("lastName", rs.getString("lastName"));
            //     usersInRole.add(user);
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching users by role: " + e.getMessage());
        }
        */

        // For demonstration, return dummy users for a specific role
        if ("Admin".equals(role) && "Default".equals(deptCode)) {
            Map<String, Object> AdminUser = new HashMap<>();
            AdminUser.put("id", 1);
            AdminUser.put("firstName", "Admin");
            AdminUser.put("lastName", "");
            AdminUser.put("userName", " Admin ");
            AdminUser.put("status", "Active");
            AdminUser.put("userType", "INT");
            AdminUser.put("email", "Admin@aivhub.com");
            AdminUser.put("homeFolder", "/Admin");
            AdminUser.put("backupUserId", "1");
            AdminUser.put("managerUserId", null);
            AdminUser.put("default_dashboard", null);
            AdminUser.put("landing_page", "Documents/Reports");
            AdminUser.put("locale", "en");
            AdminUser.put("timezone", "SYSTEM");
            AdminUser.put("theme", "Default");
            AdminUser.put("notification", "0");
            AdminUser.put("department", "Default");
            AdminUser.put("showname", "1");
            AdminUser.put("showimage", "1");
            AdminUser.put("dashboardOption", "0");
            AdminUser.put("alertsOption", "0");
            AdminUser.put("reportOption", "1");
            AdminUser.put("mergeReportOption", "0");
            AdminUser.put("adhocOption", "2");
            AdminUser.put("resourceOption", "0");
            AdminUser.put("quickRunOption", "0");
            AdminUser.put("mappingOption", "0");
            AdminUser.put("messageOption", "0");
            AdminUser.put("datasetOption", "0");
            AdminUser.put("parameterOption", "0");
            AdminUser.put("annotationOption", "0");
            AdminUser.put("notificationOption", "2");
            AdminUser.put("requestOption", "0");
            AdminUser.put("AdminOption", "1");
            AdminUser.put("scheduleOption", "0");
            AdminUser.put("webhookOption", "0");
            usersInRole.add(AdminUser);
        }

        return usersInRole;
    }

    /**
     * Selects roles assigned to a specific user.
     * This method should query your user and role stores to find roles associated with the given user.
     *
     * @param user The username to search for.
     * @param deptCode The department code.
     * @return A list of maps, where each map represents a role assigned to the user. Each role map should contain at least "name".
     */
    @Override
    public List<Map<String, Object>> selectRolesOfUser(String user, String deptCode) {
        List<Map<String, Object>> rolesOfUser = new ArrayList<>();

        // --- YOUR CUSTOM LOGIC TO FETCH ROLES BY USER HERE ---
        // Example: Fetching from a database (conceptual, assuming ai_user_role table)
        /*
        try {
            // String sql = "SELECT r.name, r.description FROM ai_role r JOIN ai_user_role ur ON r.name = ur.roleName WHERE ur.userName = ? AND r.department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, user);
            // ps.setString(2, deptCode);
            // ResultSet rs = ps.executeQuery();
            // while (rs.next()) {
            //     Map<String, Object> role = new HashMap<>();
            //     role.put("name", rs.getString("name"));
            //     role.put("description", rs.getString("description"));
            //     rolesOfUser.add(role);
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching roles by user: " + e.getMessage());
        }
        */

        // For demonstration, return dummy roles for a specific user
        if ("Admin".equals(user) && "Default".equals(deptCode)) {
            Map<String, Object> AdminRole = new HashMap<>();
            AdminRole.put("id", 1);
            AdminRole.put("name", "Administrator");
            AdminRole.put("email", "Admin@activeintelligence.co.uk");
            AdminRole.put("description", "Administrator Role");
            AdminRole.put("dashboardOption", "2");
            AdminRole.put("alertsOption", "2");
            AdminRole.put("reportOption", "2");
            AdminRole.put("mergeReportOption", "2");
            AdminRole.put("adhocOption", "2");
            AdminRole.put("resourceOption", "2");
            AdminRole.put("quickRunOption", "2");
            AdminRole.put("mappingOption", "2");
            AdminRole.put("messageOption", "2");
            AdminRole.put("datasetOption", "2");
            AdminRole.put("parameterOption", "2");
            AdminRole.put("annotationOption", "2");
            AdminRole.put("notificationOption", "2");
            AdminRole.put("requestOption", "2");
            AdminRole.put("AdminOption", "2");
            AdminRole.put("scheduleOption", "2");
            AdminRole.put("webhookOption", "0");
            AdminRole.put("department", "Default");
            rolesOfUser.add(AdminRole);
        }

        return rolesOfUser;
    }

    /**
     * Checks if a role with the given name exists in the specified department.
     * This method should query your role store to verify the existence of a role.
     *
     * @param name The role name to check.
     * @param deptCode The department code.
     * @return true if the role exists, false otherwise.
     */
    @Override
    public boolean isRoleExists(String name, String deptCode) {
        // --- YOUR CUSTOM LOGIC TO CHECK ROLE EXISTENCE HERE ---
        // Example: Checking in a database (conceptual)
        /*
        try {
            // String sql = "SELECT COUNT(*) FROM ai_role WHERE name = ? AND department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, name);
            // ps.setString(2, deptCode);
            // ResultSet rs = ps.executeQuery();
            // if (rs.next() && rs.getInt(1) > 0) {
            //     return true;
            // }
        } catch (SQLException e) {
            System.err.println("Error checking role existence: " + e.getMessage());
        }
        */

        // For demonstration
        return "Administrator".equals(name) && "Default".equals(deptCode);
    }

    /**
     * Checks if a user with the given username exists.
     * This method should query your user store to verify the existence of a user.
     *
     * @param name The username to check.
     * @param deptCode The department code.
     * @return true if the user exists, false otherwise.
     */
    @Override
    public boolean isUserExists(String name, String deptCode) {
        // --- YOUR CUSTOM LOGIC TO CHECK USER EXISTENCE HERE ---
        // Example: Checking in a database (conceptual)
        /*
        try {
            // String sql = "SELECT COUNT(*) FROM ai_user WHERE userName = ? AND department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, name);
            // ps.setString(2, deptCode);
            // ResultSet rs = ps.executeQuery();
            // if (rs.next() && rs.getInt(1) > 0) {
            //     return true;
            // }
        } catch (SQLException e) {
            System.err.println("Error checking user existence: " + e.getMessage());
        }
        */

        // For demonstration
        return "Admin".equals(name) && "Default".equals(deptCode);
    }

    /**
     * Retrieves user details by username.
     * This method should query your user store and return a map containing the user's full details.
     *
     * @param userName The username to retrieve details for.
     * @param deptCode The department code.
     * @param map Additional parameters.
     * @return A map containing user details (e.g., "userName", "firstName", "lastName", "email", etc.), or null if not found.
     */
    @Override
    public Map<String, Object> getUserByName(String userName, String deptCode, Map<String, Object> map) {
        // --- YOUR CUSTOM LOGIC TO GET USER DETAILS BY NAME HERE ---
        // Example: Fetching from a database (conceptual)
        /*
        try {
            // String sql = "SELECT * FROM ai_user WHERE userName = ? AND department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, userName);
            // ps.setString(2, deptCode);
            // ResultSet rs = ps.executeQuery();
            // if (rs.next()) {
            //     Map<String, Object> userDetails = new HashMap<>();
            //     // Populate userDetails from rs
            //     userDetails.put("userName", rs.getString("userName"));
            //     userDetails.put("firstName", rs.getString("firstName"));
            //     // ... add all other columns
            //     return userDetails;
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching user by name: " + e.getMessage());
        }
        */

        // For demonstration
        if ("Admin".equals(userName) && "Default".equals(deptCode)) {
            Map<String, Object> userDetails = new HashMap<>();
            userDetails.put("id", 1);
            userDetails.put("firstName", "Admin");
            userDetails.put("lastName", "");
            userDetails.put("userName", " Admin ");
            userDetails.put("status", "Active");
            userDetails.put("userType", "INT");
            userDetails.put("email", "admin@aivhub.com");
            userDetails.put("homeFolder", "/Admin");
            userDetails.put("backupUserId", "1");
            userDetails.put("managerUserId", null);
            userDetails.put("default_dashboard", null);
            userDetails.put("landing_page", "Documents/Reports");
            userDetails.put("locale", "en");
            userDetails.put("timezone", "SYSTEM");
            userDetails.put("theme", "Default");
            userDetails.put("notification", "0");
            userDetails.put("department", "Default");
            userDetails.put("showname", "1");
            userDetails.put("showimage", "1");
            userDetails.put("dashboardOption", "0");
            userDetails.put("alertsOption", "0");
            userDetails.put("reportOption", "1");
            userDetails.put("mergeReportOption", "0");
            userDetails.put("adhocOption", "2");
            userDetails.put("resourceOption", "0");
            userDetails.put("quickRunOption", "0");
            userDetails.put("mappingOption", "0");
            userDetails.put("messageOption", "0");
            userDetails.put("datasetOption", "0");
            userDetails.put("parameterOption", "0");
            userDetails.put("annotationOption", "0");
            userDetails.put("notificationOption", "2");
            userDetails.put("requestOption", "0");
            userDetails.put("adminOption", "1");
            userDetails.put("scheduleOption", "0");
            userDetails.put("webhookOption", "0");
            // Add other relevant user details as per ai_user table schema
            return userDetails;
        }
        return null;
    }

    /**
     * Retrieves role details by role name.
     * This method should query your role store and return a map containing the role's full details.
     *
     * @param roleName The role name to retrieve details for.
     * @param deptCode The department code.
     * @param map Additional parameters.
     * @return A map containing role details (e.g., "name", "description", "dashboardOption", etc.), or null if not found.
     */
    @Override
    public Map<String, Object> getRoleByName(String roleName, String deptCode, Map<String, Object> map) {
        // --- YOUR CUSTOM LOGIC TO GET ROLE DETAILS BY NAME HERE ---
        // Example: Fetching from a database (conceptual)
        /*
        try {
            // String sql = "SELECT * FROM ai_role WHERE name = ? AND department = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, roleName);
            // ps.setString(2, deptCode);
            // ResultSet rs = ps.executeQuery();
            // if (rs.next()) {
            //     Map<String, Object> roleDetails = new HashMap<>();
            //     // Populate roleDetails from rs
            //     roleDetails.put("name", rs.getString("name"));
            //     roleDetails.put("description", rs.getString("description"));
            //     // ... add all other columns
            //     return roleDetails;
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching role by name: " + e.getMessage());
        }
        */

        // For demonstration
        if ("Admin".equals(roleName) && "Default".equals(deptCode)) {
            Map<String, Object> roleDetails = new HashMap<>();
            roleDetails.put("id", 1);
            roleDetails.put("name", "Administrator");
            roleDetails.put("email", "admin@activeintelligence.co.uk");
            roleDetails.put("description", "Administrator Role");
            roleDetails.put("dashboardOption", "2");
            roleDetails.put("alertsOption", "2");
            roleDetails.put("reportOption", "2");
            roleDetails.put("mergeReportOption", "2");
            roleDetails.put("adhocOption", "2");
            roleDetails.put("resourceOption", "2");
            roleDetails.put("quickRunOption", "2");
            roleDetails.put("mappingOption", "2");
            roleDetails.put("messageOption", "2");
            roleDetails.put("datasetOption", "2");
            roleDetails.put("parameterOption", "2");
            roleDetails.put("annotationOption", "2");
            roleDetails.put("notificationOption", "2");
            roleDetails.put("requestOption", "2");
            roleDetails.put("adminOption", "2");
            roleDetails.put("scheduleOption", "2");
            roleDetails.put("webhookOption", "0");
            roleDetails.put("department", "Default");
            // Add other relevant role details as per ai_role table schema
            return roleDetails;
        }
        return null;
    }

    /**
     * Creates or edits a user.
     * This method should handle both creating a new user record and updating an existing one.
     * The `data` map will contain all necessary user attributes.
     *
     * @param data A map containing user data. Key fields include "userName", "password", "firstName", "lastName",
     *             "email", "department", and various feature options. It should also contain a boolean `editFlag`
     *             (true for update, false for create) and `pwdChngFlag` (true if password is being changed).
     * @param deptCode The department code the user belongs to.
     * @return The ID of the created/updated user (e.g., 1 for success, 0 for no change, -1 on error).
     */
    @Override
    public int CreateEditUser(Map<String, Object> data, String deptCode) {
        String userName = (String) data.get("userName");
        Boolean editFlag = (Boolean) data.getOrDefault("editFlag", false);
        Boolean pwdChngFlag = (Boolean) data.getOrDefault("pwdChngFlag", false);

        // --- YOUR CUSTOM LOGIC TO CREATE/EDIT USER HERE ---
        // Example: Persisting to a database (conceptual)
        /*
        try {
            if (editFlag) {
                // Update existing user
                // String sql = "UPDATE ai_user SET firstName=?, lastName=?, email=?, ... WHERE userName=? AND department=?";
                // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
                // ps.setString(1, (String) data.get("firstName"));
                // ... set other parameters
                // if (pwdChngFlag) { ps.setString(..., hashPassword((String)data.get("password"), (String)data.get("salt"))); }
                // ps.setString(..., userName);
                // ps.setString(..., deptCode);
                // return ps.executeUpdate();
            } else {
                // Create new user
                // String sql = "INSERT INTO ai_user (userName, password, firstName, ...) VALUES (?, ?, ?, ...)";
                // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
                // ps.setString(1, userName);
                // ps.setString(2, hashPassword((String)data.get("password"), (String)data.get("salt")));
                // ... set other parameters
                // return ps.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Error creating/editing user: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        if (editFlag) {
            System.out.println("Updating user: " + userName + " in department: " + deptCode);
            return 1; // Simulate success
        } else {
            System.out.println("Creating new user: " + userName + " in department: " + deptCode);
            return 1; // Simulate success
        }
    }

    /**
     * Creates or edits a role.
     * This method should handle both creating a new role record and updating an existing one.
     * The `data` map will contain all necessary role attributes.
     *
     * @param data A map containing role data. Key fields include "name", "description", "email",
     *             "department", and various feature options. It should also contain a boolean `editFlag`.
     * @param deptCode The department code the role belongs to.
     * @return The ID of the created/updated role (e.g., 1 for success, 0 for no change, -1 on error).
     */
    @Override
    public int CreateEditRole(Map<String, Object> data, String deptCode) {
        String roleName = (String) data.get("name");
        Boolean editFlag = (Boolean) data.getOrDefault("editFlag", false);

        // --- YOUR CUSTOM LOGIC TO CREATE/EDIT ROLE HERE ---
        // Example: Persisting to a database (conceptual)
        /*
        try {
            if (editFlag) {
                // Update existing role
                // String sql = "UPDATE ai_role SET description=?, email=?, ... WHERE name=? AND department=?";
                // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
                // ps.setString(1, (String) data.get("description"));
                // ... set other parameters
                // ps.setString(..., roleName);
                // ps.setString(..., deptCode);
                // return ps.executeUpdate();
            } else {
                // Create new role
                // String sql = "INSERT INTO ai_role (name, description, ...) VALUES (?, ?, ...)";
                // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
                // ps.setString(1, roleName);
                // ps.setString(2, (String) data.get("description"));
                // ... set other parameters
                // return ps.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Error creating/editing role: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        if (editFlag) {
            System.out.println("Updating role: " + roleName + " in department: " + deptCode);
            return 1; // Simulate success
        } else {
            System.out.println("Creating new role: " + roleName + " in department: " + deptCode);
            return 1; // Simulate success
        }
    }

    /**
     * Creates or edits a department.
     * This method should handle both creating a new department record and updating an existing one.
     * The `data` map will contain all necessary department attributes.
     *
     * @param data A map containing department data. Key fields include "deptname", "deptcode".
     *             It should also contain a boolean `editFlag`.
     * @param deptCode The department code (relevant for context, but the operation is on the department itself).
     * @return The ID of the created/updated department (e.g., 1 for success, 0 for no change, -1 on error).
     */
    @Override
    public int CreateEditDepartment(Map<String, Object> data, String deptCode) {
        String departmentCode = (String) data.get("deptcode");
        Boolean editFlag = (Boolean) data.getOrDefault("editFlag", false);

        // --- YOUR CUSTOM LOGIC TO CREATE/EDIT DEPARTMENT HERE ---
        // Example: Persisting to a database (conceptual)
        /*
        try {
            if (editFlag) {
                // Update existing department
                // String sql = "UPDATE ai_department SET deptname=? WHERE deptcode=?";
                // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
                // ps.setString(1, (String) data.get("deptname"));
                // ps.setString(2, departmentCode);
                // return ps.executeUpdate();
            }
            else {
                // Create new department
                // String sql = "INSERT INTO ai_department (deptname, deptcode) VALUES (?, ?)";
                // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
                // ps.setString(1, (String) data.get("deptname"));
                // ps.setString(2, departmentCode);
                // return ps.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Error creating/editing department: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        if (editFlag) {
            System.out.println("Updating department: " + departmentCode);
            return 1; // Simulate success
        } else {
            System.out.println("Creating new department: " + departmentCode);
            return 1; // Simulate success
        }
    }

    /**
     * Retrieves all departments with their associated Admin users.
     * This method should query your department and user stores to link departments with their Administrators.
     *
     * @param owner The owner of the request (can be used for filtering or auditing).
     * @param deptCode The department code (can be used for filtering).
     * @return A list of maps, where each map represents a department with Admin info.
     *         Each map should contain at least "deptCode", "deptName", and "userName" (of the Admin).
     */
    @Override
    public List<Map<String, Object>> getAlldepartmentsWithAdmin(String owner, String deptCode) {
        List<Map<String, Object>> departmentsWithAdmins = new ArrayList<>();

        // --- YOUR CUSTOM LOGIC TO FETCH DEPARTMENTS WITH AdminS HERE ---
        // Example: Fetching from a database (conceptual, joining ai_department and ai_user)
        /*
        try {
            // String sql = "SELECT d.deptcode, d.deptname, u.userName FROM ai_department d LEFT JOIN ai_user u ON d.deptcode = u.department AND u.AdminOption = 2";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, deptCode);
            // ResultSet rs = ps.executeQuery();
            // while (rs.next()) {
            //     Map<String, Object> deptAdmin = new HashMap<>();
            //     deptAdmin.put("deptCode", rs.getString("deptcode"));
            //     deptAdmin.put("deptName", rs.getString("deptname"));
            //     deptAdmin.put("userName", rs.getString("userName")); // Admin user for this department
            //     departmentsWithAdmins.add(deptAdmin);
            // }
        } catch (SQLException e) {
            System.err.println("Error fetching departments with Admins: " + e.getMessage());
        }
        */

        // For demonstration
        Map<String, Object> dept1 = new HashMap<>();
        dept1.put("deptCode", "Default");
        dept1.put("deptName", "Default");
        dept1.put("userName", "Admin");
        departmentsWithAdmins.add(dept1);

        return departmentsWithAdmins;
    }

    /**
     * Deletes a department by its ID.
     * This method should remove the department record from your department store.
     *
     * @param owner The owner of the request (for auditing).
     * @param deptId A map containing the `id` of the department to delete.
     * @return The number of deleted departments (e.g., 1 for success, 0 if not found, -1 on error).
     */
    @Override
    public int deleteDeptById(String owner, Map<String, Object> deptId) {
        Integer idToDelete = (Integer) deptId.get("id");

        // --- YOUR CUSTOM LOGIC TO DELETE DEPARTMENT HERE ---
        // Example: Deleting from a database (conceptual)
        /*
        try {
            // String sql = "DELETE FROM ai_department WHERE id = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setInt(1, idToDelete);
            // return ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error deleting department by ID: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        if (idToDelete != null && idToDelete == 1) { // Simulate deleting department with ID 1
            System.out.println("Deleting department with ID: " + idToDelete);
            return 1; // Simulate success
        }
        System.out.println("Department with ID " + idToDelete + " not found or could not be deleted.");
        return 0; // Simulate not found or no change


        // This will not delete Department files and folder from repo.
    }

    /**
     * Deletes a user by username.
     * This method should remove the user record from your user store and any associated user-role mappings.
     *
     * @param userName The username of the user to delete.
     * @param deptCode The department code the user belongs to.
     * @return The number of deleted users (e.g., 1 for success, 0 if not found, -1 on error).
     */
    @Override
    public int deleteUserById(String userName, String deptCode) {
        // --- YOUR CUSTOM LOGIC TO DELETE USER HERE ---
        // Example: Deleting from a database (conceptual)
        /*
        try {
            // First, delete from ai_user_role table to maintain referential integrity
            // String deleteRolesSql = "DELETE FROM ai_user_role WHERE userName = ?";
            // PreparedStatement psRoles = dataSource.getConnection().prepareStatement(deleteRolesSql);
            // psRoles.setString(1, userName);
            // psRoles.executeUpdate();

            // Then, delete from ai_user table
            // String deleteUserSql = "DELETE FROM ai_user WHERE userName = ? AND department = ?";
            // PreparedStatement psUser = dataSource.getConnection().prepareStatement(deleteUserSql);
            // psUser.setString(1, userName);
            // psUser.setString(2, deptCode);
            // return psUser.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error deleting user by username: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        if ("testuser".equals(userName) && "Default".equals(deptCode)) { // Simulate deleting 'testuser'
            System.out.println("Deleting user: " + userName + " from department: " + deptCode);
            return 1; // Simulate success
        }
        System.out.println("User " + userName + " not found or could not be deleted.");
        return 0; // Simulate not found or no change
    }

    /**
     * Deletes a role by role name.
     * This method should remove the role record from your role store and any associated user-role mappings.
     *
     * @param roleName The name of the role to delete.
     * @param deptCode The department code the role belongs to.
     * @return The number of deleted roles (e.g., 1 for success, 0 if not found, -1 on error).
     */
    @Override
    public int deleteRoleById(String roleName, String deptCode) {
        // --- YOUR CUSTOM LOGIC TO DELETE ROLE HERE ---
        // Example: Deleting from a database (conceptual)
        /*
        try {
            // First, delete from ai_user_role table to maintain referential integrity
            // String deleteUserRolesSql = "DELETE FROM ai_user_role WHERE roleName = ?";
            // PreparedStatement psUserRoles = dataSource.getConnection().prepareStatement(deleteUserRolesSql);
            // psUserRoles.setString(1, roleName);
            // psUserRoles.executeUpdate();

            // Then, delete from ai_role table
            // String deleteRoleSql = "DELETE FROM ai_role WHERE name = ? AND department = ?";
            // PreparedStatement psRole = dataSource.getConnection().prepareStatement(deleteRoleSql);
            // psRole.setString(1, roleName);
            // psRole.setString(2, deptCode);
            // return psRole.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error deleting role by name: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        if ("GUEST".equals(roleName) && "Default".equals(deptCode)) { // Simulate deleting 'GUEST' role
            System.out.println("Deleting role: " + roleName + " from department: " + deptCode);
            return 1; // Simulate success
        }
        System.out.println("Role " + roleName + " not found or could not be deleted.");
        return 0; // Simulate not found or no change
    }

    /**
     * Retrieves user role features.
     * This method should aggregate all permissions a user has, considering both their direct permissions
     * and the permissions granted by the roles they belong to.
     *
     * @param userName The username.
     * @param deptCode The department code.
     * @return A map containing user role features. Keys are feature names (e.g., "dashboardOption"),
     *         and values are their corresponding permission levels (0, 1, or 2).
     */
    @Override
    public Map<String, Object> getUserRoleFeatures(String userName, String deptCode) {
        Map<String, Object> userFeatures = new HashMap<>();

        // --- YOUR CUSTOM LOGIC TO AGGREGATE USER FEATURES HERE ---
        // This typically involves:
        // 1. Fetching the user's direct permissions from ai_user table.
        // 2. Fetching all roles assigned to the user from ai_user_role table.
        // 3. For each role, fetching its permissions from ai_role table.
        // 4. Merging all permissions, usually taking the highest permission level for each feature.

        // Example: Conceptual aggregation
        /*
        try {
            // Get user's direct permissions
            // Map<String, Object> directPermissions = getUserByName(userName, deptCode, null);
            // if (directPermissions != null) {
            //     userFeatures.putAll(directPermissions);
            // }

            // Get roles assigned to user
            // List<Map<String, Object>> roles = selectRolesOfUser(userName, deptCode);
            // for (Map<String, Object> role : roles) {
            //     Map<String, Object> rolePermissions = getRoleByName((String) role.get("name"), deptCode, null);
            //     if (rolePermissions != null) {
            //         // Merge permissions, taking the highest value
            //         for (Map.Entry<String, Object> entry : rolePermissions.entrySet()) {
            //             if (entry.getKey().endsWith("Option") && entry.getValue() instanceof Integer) {
            //                 Integer currentLevel = (Integer) userFeatures.getOrDefault(entry.getKey(), 0);
            //                 Integer newLevel = (Integer) entry.getValue();
            //                 userFeatures.put(entry.getKey(), Math.max(currentLevel, newLevel));
            //             }
            //         }
            //     }
            // }
        } catch (Exception e) {
            System.err.println("Error getting user role features: " + e.getMessage());
        }
        */

        // For demonstration, return some dummy features
        userFeatures.put("userName", userName);
        userFeatures.put("dashboardOption", 2);
        userFeatures.put("reportOption", 1);
        userFeatures.put("AdminOption", ("Admin".equals(userName) ? 2 : 0));
        userFeatures.put("notificationOption", 2);

        return userFeatures;
    }

    /**
     * Updates roles for a user.
     * This method should update the user-role mappings in your store.
     *
     * @param userRoleData A map containing user role data. Expected keys: "userName" (String) and "roles" (comma-separated String of role names).
     * @param updatedBy The user who performed the update (for auditing).
     * @param deptCode The department code.
     * @param traceid The trace ID for logging.
     * @return 1 on success, -1 on error.
     */
    @Override
    public int updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
        String userName = (String) userRoleData.get("userName");
        String rolesString = (String) userRoleData.get("roles");

        // --- YOUR CUSTOM LOGIC TO UPDATE USER ROLES HERE ---
        // This typically involves:
        // 1. Deleting all existing roles for the user.
        // 2. Inserting new role mappings based on the provided rolesString.

        // Example: Updating in a database (conceptual)
        /*
        try {
            // deleteRolesForUser(userName); // Call a helper method to delete existing roles

            // if (rolesString != null && !rolesString.isEmpty()) {
            //     String[] roles = rolesString.split(",");
            //     for (String role : roles) {
            //         // insertUserRole(userName, role); // Call a helper method to insert new role
            //     }
            // }
            return 1; // Simulate success
        } catch (Exception e) {
            System.err.println("Error updating roles for user: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        System.out.println("Updating roles for user " + userName + ": " + rolesString);
        return 1; // Simulate success
    }

    /**
     * Updates users for a role.
     * This method should update the user-role mappings in your store.
     *
     * @param userRoleData A map containing user role data. Expected keys: "roleName" (String) and "users" (comma-separated String of usernames).
     * @param updatedBy The user who performed the update (for auditing).
     * @param deptCode The department code.
     * @param traceid The trace ID for logging.
     * @return 1 on success, -1 on error.
     */
    @Override
    public int updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid) {
        String roleName = (String) userRoleData.get("roleName");
        String usersString = (String) userRoleData.get("users");

        // --- YOUR CUSTOM LOGIC TO UPDATE USERS FOR ROLE HERE ---
        // This typically involves:
        // 1. Deleting all existing users for the role.
        // 2. Inserting new user mappings based on the provided usersString.

        // Example: Updating in a database (conceptual)
        /*
        try {
            // deleteUsersForRole(roleName); // Call a helper method to delete existing users for role

            // if (usersString != null && !usersString.isEmpty()) {
            //     String[] users = usersString.split(",");
            //     for (String user : users) {
            //         // insertUserRole(user, roleName); // Call a helper method to insert new user for role
            //     }
            // }
            return 1; // Simulate success
        } catch (Exception e) {
            System.err.println("Error updating users for role: " + e.getMessage());
            return -1;
        }
        */

        // For demonstration
        System.out.println("Updating users for role " + roleName + ": " + usersString);
        return 1; // Simulate success
    }

    /**
     * Checks if a department exists.
     * This method should query your department store to verify the existence of a department.
     *
     * @param deptCode The department code to check.
     * @param traceid The trace ID for logging.
     * @return true if the department exists, false otherwise.
     */
    @Override
    public boolean deptExists(String deptCode, String traceid) {
        // --- YOUR CUSTOM LOGIC TO CHECK DEPARTMENT EXISTENCE HERE ---
        // Example: Checking in a database (conceptual)
        /*
        try {
            // String sql = "SELECT COUNT(*) FROM ai_department WHERE deptcode = ?";
            // PreparedStatement ps = dataSource.getConnection().prepareStatement(sql);
            // ps.setString(1, deptCode);
            // ResultSet rs = ps.executeQuery();
            // if (rs.next() && rs.getInt(1) > 0) {
            //     return true;
            // }
        } catch (SQLException e) {
            System.err.println("Error checking department existence: " + e.getMessage());
        }
        */

        // For demonstration
        return "Default".equals(deptCode) || "sales".equals(deptCode);
    }

    /**
     * Retrieves user authentication details after a certain time or for session management.
     * This method might be used to refresh user session data or retrieve updated user information.
     *
     * @param userName The username.
     * @param dc The department code.
     * @param traceid The trace ID for logging.
     * @return A map containing authentication-related user details. This could include updated JWTs,
     *         session expiration times, or refreshed user attributes.
     */
    @Override
    public Map<String, Object> getAuthAfterTimeUser(String userName, String dc, String traceid) {
        Map<String, Object> authDetails = new HashMap<>();

        // --- YOUR CUSTOM LOGIC TO GET AUTHENTICATION DETAILS HERE ---
        // This involve:
        // 1. Fetching all user details from your store like which options dose that user have access adminOption,reportsOptions etc.
        //  (if  your system do not contains all this information you can read from properties file and set.)
        

        authDetails.put("adhocOption", "2");
        authDetails.put("adminOption", "2");
        authDetails.put("alertsOption", "2");
        authDetails.put("annotationOption", "2");
        authDetails.put("backupFor", "");
        authDetails.put("backupUserId", "");
        authDetails.put("dashboardOption", "2");
        authDetails.put("datasetOption", "2");
        authDetails.put("default_dashboard", "571|:|ChartParams|:|Admin"); // or null
        authDetails.put("department", "Default");
        authDetails.put("email", "admin@aivhub.com");
        authDetails.put("firstName", "Admin");
        authDetails.put("homeFolder", "/Admin");
        authDetails.put("landing_page", "Documents/Reports");
        authDetails.put("lastName", null);
        authDetails.put("locale", "en");
        authDetails.put("managerUserId", "0");
        authDetails.put("mappingOption", "2");
        authDetails.put("mergeReportOption", "2");
        authDetails.put("messageOption", "2");
        authDetails.put("notification", "0");
        authDetails.put("notificationOption", "2");
        authDetails.put("parameterOption", "2");
        authDetails.put("quickRunOption", "2");
        authDetails.put("reportOption", "2");
        authDetails.put("requestOption", "2");
        authDetails.put("resourceOption", "2");
        authDetails.put("scheduleOption", "2");
        authDetails.put("webhookOption", "2");
        authDetails.put("showimage", "1");
        authDetails.put("showname", "1");
        authDetails.put("status", "Active");
        authDetails.put("theme", null);
        authDetails.put("timezone", "SYSTEM");
        authDetails.put("userName", "Admin");
        authDetails.put("userType", "INT");
        authDetails.put("roles", "Administrator,Sales,Role1");
        authDetails.put("owner", "Admin");
        return authDetails;
    }

    /**
     * Generates an embedded token.
     * This method is used to create a token that can be embedded in URLs or other contexts
     * for specific, often temporary, authentication or authorization purposes.
     *
     * @param data A map containing data for token generation (e.g., "userName", "permissions", "expiration").
     * @param deptCode The department code.
     * @param traceid The trace ID for logging.
     * @return The generated embedded token as a String.
     */
    @Override
    public String generateEmbedToken(Map<String, Object> data, String deptCode, String traceid) {

        String userName = (String) data.get("userName");
        // Other data from the map could include specific permissions, expiration time, etc.

        // --- YOUR CUSTOM LOGIC TO GENERATE EMBEDDED TOKEN HERE ---
        // This might involve:
        // 1. Creating a short-lived JWT with specific claims.
        // 2. Generating a unique, cryptographically secure token and storing its mapping to user/permissions.

        // The following is a basic placeholder for demonstration purposes only.
        // Example: Simple token generation (replace with robust security practices)
        String embeddedToken = "embed_token_for_" + userName + "_" + System.currentTimeMillis();

        System.out.println("Generated embedded token for " + userName + ": " + embeddedToken);

        return embeddedToken;
    }
}
```
</details>

### Registering Your Custom `IAuthentication` Implementation

Once you have implemented your custom `IAuthentication` class, you need to register it as a Spring Bean so that the application can use it. You can do this in your main application class or a separate configuration class.

**Example (in your main application class):**


### Authentication Flow

Understanding the flow of control is crucial for debugging and extending the application. Here's a simplified overview of how a request is processed through the security layer:

1.  **Client Request:** A client (e.g., web browser, mobile app) sends an HTTP request to the Spring Boot application.
2.  **`FirstFilter` Interception:** The `FirstFilter` (`com.security.services.FirstFilter`), configured with `@WebFilter("/*")` and `@Order(Ordered.LOWEST_PRECEDENCE)`, is the initial entry point for all incoming requests.
    *   **Parameter Sanitization:** It performs a basic security check by iterating through all request parameters (`req.getParameterNames()`) and checking their values for newline characters (`` or `
`). If found, it throws an `IOException` to prevent potential injection attacks.
    *   **URI Whitelisting:** The filter checks if the request URI matches a predefined whitelist of patterns (e.g., static resources like `.html`, `.css`, `.js`, `.png`, etc., and specific application endpoints like `/v3/`, `/external/update_user_role`, `/api/user/validate`, `/aiv/logout`, `/allow/callback`, `/dept_list`, `/iconFile.json`, `/license_info`, `/endpoint/executed`, `/aivverion`). If a match is found, the request bypasses further security checks and proceeds directly down the filter chain.
    *   **Authentication Endpoint Handling (`/authenticate`):**
        *   If a `POST` request is made to `/authenticate`, the filter reads the request body as a `String` using `IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8)`.
        *   It then parses this string into a `JSONObject` to extract `userName`, `password`, `deptCode`, and `salt`.
        *   If the `embed` flag is true in the JSON, the `password` is decrypted using `PaaswordCryptography.decryptEmbedPass()`.
        *   It constructs a `Map<String, Object>` (`user`) with extracted and processed credentials, including a newly generated JWT token (`utoken`) for the user.
        *   The authentication is delegated to `new DefaultAuthenticateImpl().authenticated(user, deptCode)`.
        *   On successful authentication, the response content type is set to `application/json`, character encoding to `UTF-8`, and a `302` redirect is issued to a specific SSO login URL, appending the authentication response data.
        *   If authentication fails, "Session Expired" is printed to the response.
    *   **Embedded External Authentication (`/embed/external/`):**
        *   For `GET` requests to `/embed/external/` (without a query string), it parses the URI path to extract `deptCode`, `userName`, `password`, and `token` from specially formatted segments (e.g., `a_d__`, `a_u__`, `a_p__`, `a_t__`).
        *   It decrypts the embedded password using `PaaswordCryptography.decryptEmbedPass()`.
        *   It constructs a `Map<String, Object>` (`passData`) with these details, including a newly generated JWT token.
        *   Authentication is delegated to `new DefaultAuthenticateImpl().authenticated(passData, deptCode)`.
        *   On success, it adds an `auth-token` header and redirects the user to the original URI with the authentication response.
    *   **Session Refresh (`/re_schedule_session`):**
        *   Retrieves the `X-XSRFTOKEN` from headers or parameters.
        *   Extends the token's expiration using `new JwtTokenUtil().extendTokenExpiration()`.
        *   Adds the refreshed token to the `auth-token` response header.
    *   **Logout (`/v5/api/logout`):**
        *   Prints `true` to the response.
        *   Retrieves `stoken` from headers or parameters and attempts to invalidate the token.
    *   **General Authenticated Requests:** For other requests that are not whitelisted but require authentication (e.g., `/v5` endpoints or file operations), the filter checks for the `X-XSRFTOKEN` header. If present, it attempts to extend the token's expiration. If an `apitoken` header is present, it allows the request to proceed without further token validation, assuming an API-based authentication.
    *   **Default Forwarding:** If none of the specific conditions are met, the filter simply calls `chain.doFilter(request, response)`, allowing the request to proceed to the next filter in the chain or the target servlet/controller.
4.  **Authentication Logic (via `IAuthentication`):**
    *   If the request is for the `/authenticate` endpoint, the `AuthenticationFilter` will typically extract credentials (username, password, deptCode, salt) from the request.
    *   It then calls the `authenticate()` method of the `IAuthentication` implementation (e.g., `SimpleAuthImpl` or your `CustomAuthenticationImpl`).
    *   The `authenticate()` method validates the credentials. In `SimpleAuthImpl`, this involves calling `SimpleAuthService.validatePassword()`, which hashes the provided password (using `Be.decrypt` and `CommonConfig.md5String`) and compares it to the stored hash in the `ai_user` table.
    *   If authentication is successful, `authenticate()` returns a `Map` of user details.
5.  **JWT Handling:**
    *   Upon successful authentication, `DefaultAuthenticateImpl.authenticated()` (which is called by the controller or filter) generates a JWT using `JwtTokenUtil.generateToken()`. This token is then typically set in the response header.
    *   For subsequent requests, the `AuthenticationFilter` (or other components) will extract the JWT from the request header. `CommonConfig.isAuthneticated()` (which uses `JwtTokenUtil.validateToken()`) is then called to validate the token's signature and expiration.
6.  **Response Handling:**
    *   If authentication is successful, the request proceeds down the filter chain to the intended resource. For the `/authenticate` endpoint, the generated JWT is typically returned in a response header.
    *   If authentication fails at any point, the filter sends a "Session Expired" message to the client and terminates the request, preventing unauthorized access.

## Authorization

The application implements role-based access control (RBAC) to manage user permissions and control access to various features.

### Roles and Permissions

*   **Roles:** Users are assigned to one or more roles (e.g., "Admin", "user", "viewer"). Roles are logical groupings of permissions.
*   **Permissions (Features):** Each role and individual user can have a set of permissions that define what actions they can perform or what features they can access. These permissions are represented by properties like `dashboardOption`, `AdminOption`, `reportOption`, `adhocOption`, etc.
*   **Configuration:** These permissions are initially configured in the `src/main/resources/user_Default.properties` file and are stored in the database (`ai_user` and `ai_role` tables).

The value of each permission property determines the level of access:

*   `0`: No access / Disabled
*   `1`: Read-only access (where applicable)
*   `2`: Full access / Enabled

### Managing Users, Roles, and Departments

The `IAuthentication` interface provides a comprehensive set of methods for managing users, roles, and departments within the system. Your custom `IAuthentication` implementation will be responsible for persisting and retrieving this data, typically from the configured database.

Here's a breakdown of the key management methods:

*   **`CreateEditUser(Map<String, Object> data, String deptCode)`:**
    *   **Purpose:** Creates a new user or updates an existing one.
    *   **`data` Map:** Should contain user details such as `userName`, `firstName`, `lastName`, `email`, `password`, `status`, `userType`, `homeFolder`, and various feature options (e.g., `dashboardOption`, `AdminOption`). It also expects a boolean `editFlag` (true for update, false for create) and `pwdChngFlag` (true if password is being changed).
    *   **Return:** The ID of the created/updated user (e.g., 1 for success, 0 for no change, -1 on error).

*   **`CreateEditRole(Map<String, Object> data, String deptCode)`:**
    *   **Purpose:** Creates a new role or updates an existing one.
    *   **`data` Map:** Should contain role details such as `name`, `description`, `email`, and various feature options. It also expects a boolean `editFlag`.
    *   **Return:** The ID of the created/updated role (e.g., 1 for success, 0 for no change, -1 on error).

*   **`CreateEditDepartment(Map<String, Object> data, String deptCode)`:**
    *   **Purpose:** Creates a new department or updates an existing one.
    *   **`data` Map:** Should contain department details such as `deptname` and `deptcode`. It also expects a boolean `editFlag`.
    *   **Return:** The ID of the created/updated department (e.g., 1 for success, 0 for no change, -1 on error).

*   **`getAllUsers(String deptCode, Map<String, Object> map)`:**
    *   **Purpose:** Retrieves a list of all users belonging to a specific department.
    *   **Return:** A `List` of `Map<String, Object>`, where each map represents a user's details.

*   **`getAllRoles(String deptCode, Map<String, Object> map)`:**
    *   **Purpose:** Retrieves a list of all roles available in a specific department.
    *   **Return:** A `List` of `Map<String, Object>`, where each map represents a role's details.

*   **`getAllDepartments(String deptCode, Map<String, Object> data)`:**
    *   **Purpose:** Retrieves a list of all departments in the system.
    *   **Return:** A `List` of `Map<String, Object>`, where each map represents a department's details.

*   **`selectUsersOfRole(String role, String deptCode)`:**
    *   **Purpose:** Retrieves a list of users who are assigned to a specific role within a department.
    *   **Return:** A `List` of `Map<String, Object>`, where each map represents a user.

*   **`selectRolesOfUser(String user, String deptCode)`:**
    *   **Purpose:** Retrieves a list of roles assigned to a specific user within a department.
    *   **Return:** A `List` of `Map<String, Object>`, where each map represents a role.

*   **`updateRolesForUser(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid)`:**
    *   **Purpose:** Updates the roles assigned to a specific user.
    *   **`userRoleData` Map:** Should contain `userName` and a comma-separated string of `roles` (e.g., "role1,role2").
    *   **Return:** 1 on success, -1 on error.

*   **`updateUsersForRole(Map<String, Object> userRoleData, String updatedBy, String deptCode, String traceid)`:**
    *   **Purpose:** Updates the users assigned to a specific role.
    *   **`userRoleData` Map:** Should contain `roleName` and a comma-separated string of `users` (e.g., "user1,user2").
    *   **Return:** 1 on success, -1 on error.

*   **`deleteUserById(String userName, String deptCode)`:**
    *   **Purpose:** Deletes a user from the system.
    *   **Return:** The number of deleted users, or -1 on error.

*   **`deleteRoleById(String roleName, String deptCode)`:**
    *   **Purpose:** Deletes a role from the system.
    *   **Return:** The number of deleted roles, or -1 on error.

*   **`deleteDeptById(String owner, Map<String, Object> deptId)`:**
    *   **Purpose:** Deletes a department from the system.
    *   **`deptId` Map:** Should contain the `id` of the department to delete.
    *   **Return:** The number of deleted departments, or -1 on error).

*   **`isRoleExists(String name, String deptCode)`:**
    *   **Purpose:** Checks if a role with the given name exists in the specified department.
    *   **Return:** `true` if the role exists, `false` otherwise.

*   **`isUserExists(String name, String deptCode)`:**
    *   **Purpose:** Checks if a user with the given username exists.
    *   **Return:** `true` if the user exists, `false` otherwise.

*   **`getUserByName(String userName, String deptCode, Map<String, Object> map)`:**
    *   **Purpose:** Retrieves detailed information for a specific user by their username.
    *   **Return:** A `Map<String, Object>` containing the user's details, or `null` if not found.

*   **`getRoleByName(String roleName, String deptCode, Map<String, Object> map)`:**
    *   **Purpose:** Retrieves detailed information for a specific role by its name.
    *   **Return:** A `Map<String, Object>` containing the role's details, or `null` if not found.

*   **`getUserRoleFeatures(String userName, String deptCode)`:**
    *   **Purpose:** Retrieves the combined features/permissions for a given user, considering both their individual settings and the roles they belong to.
    *   **Return:** A `Map<String, Object>` containing the user's effective permissions.

*   **`getAlldepartmentsWithAdmin(String owner, String deptCode)`:**
    *   **Purpose:** Retrieves a list of all departments along with information about their associated Admin users.
    *   **Return:** A `List` of `Map<String, Object>`.

*   **`deptExists(String deptCode, String traceid)`:**
    *   **Purpose:** Checks if a department with the given code exists.
    *   **Return:** `true` if the department exists, `false` otherwise.

*   **`getAuthAfterTimeUser(String userName, String dc, String traceid)`:**
    *   **Purpose:** Retrieves user authentication details after a certain time or for session management.
    *   **Return:** A `Map<String, Object>` containing authentication-related user details.

*   **`generateEmbedToken(Map<String, Object> data, String deptCode, String traceid)`:**
    *   **Purpose:** Generates a token for embedded authentication scenarios.
    *   **Return:** A `String` representing the generated embedded token.
