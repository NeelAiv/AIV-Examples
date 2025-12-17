# AIV PostgreSQL Security Integration

## 1. Overview

This project is a Spring Boot security module designed to integrate the AIV platform with a **PostgreSQL** database for user authentication and authorization. It serves as an alternative to external IdPs like Keycloak, managing users, roles, and permissions directly within a dedicated security database schema.

The module implements AIV's `IAuthentication` interface to provide seamless login capabilities using standard username and password credentials stored securely in the database.

### Key Features of this Implementation

*   **Implements `IAuthentication`:** Integrates with the AIV security framework via `SimpleAuthImpl`, acting as the bridge between AIV and the database.
*   **Database-Driven Security:** All users, roles, and department mappings are stored in a PostgreSQL database, allowing for complete control over the security model schema.
*   **Encrypted Passwords:** Utilizes `PaaswordCryptography` and encryption utilities to ensure sensitive credentials are not stored in plain text.
*   **Dual Authentication Support:** Supports both standard direct login (Username/Password) and Embed/Token-based authentication.
*   **Custom Filter Chain:** Uses `AuthenticationFilter` to intercept requests, validating sessions and tokens for secured endpoints while allowing public access to necessary resources.

## 2. How It Works

This module replaces AIV's default security with a database-backed authentication flow.

### The `IAuthentication` Implementation: `SimpleAuthImpl.java`

This class is the core adapter for the module. Its primary responsibility is to interact with the database via `SimpleAuthService` to validate credentials and retrieve user metadata.

*   **Authentication:** The `authenticate(Map<String, Object> map)` method receives credentials from the frontend. It uses `SimpleAuthService.validatePassword()` to check the hash against the database.
*   **Data Fetching:** Methods like `getAllUsers()`, `getAllRoles()`, and `getUserRoleFeatures()` query the `datasource1` (Security DB) to populate the AIV user profile.
*   **User Provisioning:** Supports creating and updating users, roles, and departments directly through the `CreateEditUser`, `CreateEditRole`, and `CreateEditDepartment` methods.

### Data Source: Security Database

All user data is stored in the connection defined as `datasource1` in the AIV configuration.

*   **Users & Roles:** Managed directly in the database tables (accessed via `SimpleAuthService`).
*   **Permissions:** Similar to other modules, fine-grained permissions (e.g., `dashboardOption`) are retrieved and mapped to the user session, often defaulting to values in `user_default.properties` if not explicitly overridden.

### Authentication Flow

1.  **Login Request:** A user submits their credentials on the AIV login page.
2.  **Verification:** `SimpleAuthImpl` validates the username and password against the database.
3.  **Session Creation:** Upon success, `DefaultAuthenticateImpl.authenticated()` is called.
4.  **Token Generation:** `HeaderSecurity` generates an encrypted session payload (and potentially a trace ID).
5.  **Context Establishment:** The user's profile, including their roles and department code (`deptCode`), is established in the session.
6.  **Request Filtering:** Subsequent requests are intercepted by `AuthenticationFilter`, which checks for valid session attributes or tokens before allowing access to protected API endpoints.

## 3. Configuration

Configuration is primarily handled in the AIV `application.properties` file.

### AIV `application.properties`

The following properties must be configured in your AIV `application.properties` (or `.yml`) file.

1.  **Set the Custom Security Class:**
    This tells AIV to use this PostgreSQL integration.
    ```properties
    app.securityClass: com.security.services.SimpleAuthImpl
    ```

2.  **Configure Security Datasource (`datasource1`):**
    This block defines the connection to your security database.
    ```yaml
    spring:
      datasource1:
        url: jdbc:postgresql://[YOUR_DB_HOST]:[PORT]/[SECURITY_DB_NAME]
        username: [DB_USER]
        password: [DB_PASSWORD]
        driverClassName: org.postgresql.Driver
    ```

3.  **Database Initialization:**
    When creating a new department, the system uses the `ai_postgresql_general.sql` file (located in `repository/econfig/`) to initialize the necessary schema and tables. Ensure this file is present and up-to-date.

### Example `application.properties` snippet

<details>
<summary><strong>Click</strong> to view an example configuration</summary>

```yaml
spring:
  datasource1:
    url: jdbc:postgresql://localhost:5432/aiv_security
    username: postgres
    password: password
    driverClassName: org.postgresql.Driver
    
app:
  securityClass: com.security.services.SimpleAuthImpl
  database: postgresql
```
</details>

## 4. Component Breakdown

*   **`SimpleAuthImpl.java`**: The main entry point for AIV to interact with the security module. Handles authentication, user management, and role retrieval.
*   **`SimpleAuthService.java`**: The service layer that performs the actual JDBC/SQL queries against `datasource1`.
*   **`DefaultAuthenticateImpl.java`**: Manages the successful authentication lifecycle, generating session tokens and audit logs.
*   **`AuthenticationFilter.java`**: A Servlet filter that secures endpoints, ensuring only authenticated requests (or those with valid JWT/Embed tokens) can access protected resources. It whitelists static resources and public APIs.
*   **`SecurityConfig.java`**: Basic Spring Security configuration, typically set to allow requests so the custom `AuthenticationFilter` can handle the fine-grained logic.
*   **`PaaswordCryptography.java`**: Handles encryption and decryption of passwords and sensitive tokens.

## 5. Deployment and Usage

### Step 1: Build the JAR File

Open a terminal in the root directory of this project and run the Maven command:
```bash
mvn verify
```
This will create the JAR file in the `target/` folder.

### Step 2: Place the JAR File in AIV Docker

1.  **Remove or replace existing jar:** Navigate to `docker-aiv/config/drivers/` and remove or replace existing `security-postgres-2.0.0.jar`.

### Step 3: Configure AIV

Ensure your main AIV `application.properties` file (located at `docker-aiv/repository/econfig/`) contains the correct `app.securityClass` and `spring.datasource1` configurations as described in Section 3.

### Step 4: Run the Application

```bash
docker-compose up
```

### Step 5: Log In

1.  Open your browser and navigate to your AIV instance.
2.  Enter your database-defined credentials.
3.  Upon success, you will be logged in with the permissions and roles defined in your PostgreSQL security database.
