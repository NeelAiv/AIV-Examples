# AIV Keycloak SSO Integration

## 1. Overview

This project is a Spring Boot security module designed to integrate the AIV platform with **Keycloak**, a leading open-source Identity and Access Management (IAM) solution. It replaces AIV's standard authentication with a robust, standards-based **OpenID Connect (OIDC)** single sign-on (SSO) flow.

The module acts as a bridge, translating Keycloak's security model into the format AIV's backend expects, and manages the internal AIV session after a successful SSO login.

### Key Features of this Implementation

*   **Implements `IAuthentication`:** Seamlessly integrates with the AIV security framework by providing the `KeycloakAuthImpl` class, which acts as an adapter between AIV and the Keycloak Admin API.
*   **Keycloak as the Central User Store:** All users and roles are managed directly within Keycloak, eliminating the need for local user tables or files.
*   **Standard OIDC Redirect Flow:** User authentication is handled via a secure redirect to the Keycloak login page, providing a true single sign-on experience.
*   **JWT for Internal AIV Sessions:** After a successful SSO login, a separate, internal JSON Web Token (JWT) is generated to manage the user's session within AIV for API calls, with token generation and extension capabilities.
*   **Spring Security & Custom Filter Chain:** Leverages the power of Spring Security for handling the OIDC flow, while a custom `KeycloakFilter` intercepts successful logins to create the AIV-specific session.

## 2. How It Works

This module replaces AIV's default security with a modern OIDC authentication flow.

### The `IAuthentication` Implementation: `KeycloakAuthImpl.java`

This class is the **adapter** or **bridge** between AIV and Keycloak. Unlike the CSV project, it does **not** handle passwords. Its primary responsibility is to use the **Keycloak Admin REST API** to manage and retrieve user/role data on behalf of the AIV application.

*   **Data Fetching:** When AIV needs a list of users or roles (e.g., for the admin panel), methods like `getAllUsers()` and `getAllRoles()` are called. They make secure, authenticated REST API calls to Keycloak to get this data.
*   **Data Transformation:** Keycloak's API returns data in its own format. `KeycloakAuthImpl` contains "transformer" methods (e.g., `buildAivUserProfile`) that convert this raw data into the exact JSON structure that the AIV frontend expects, preventing UI errors.
*   **User Provisioning:** When a new user logs in for the first time, the `checkUser()` logic uses `KeycloakAuthImpl.isUserExists()` and `CreateEditUser()` to automatically create a corresponding user account within Keycloak if one doesn't already exist.

### Data Source: Keycloak Server

All user and role data is stored and managed within the Keycloak server. This provides a central, secure, and feature-rich platform for identity management.

*   **Users:** All application users are created and managed in the `Users` section of a Keycloak realm.
*   **Roles:** Application-specific roles (like `admin`, `default-user`) are created as `Realm Roles` in Keycloak.
*   **Permissions:** The fine-grained permissions for AIV (e.g., `dashboardOption`, `reportOption`) are not stored in Keycloak directly. Instead, they are defined in the `user_default.properties` file and are dynamically applied by the `KeycloakAuthImpl` class based on which roles a user has.

### Authentication and Session Flow

1.  A user navigates to an AIV entry point (e.g., `http://192.168.31.65:8087/aiv`).
2.  Since the user is not authenticated, Spring Security's OAuth2/OIDC filter chain intercepts the request.
3.  The user's browser is redirected to the **Keycloak login page**.
4.  The user enters their credentials **at Keycloak**.
5.  Upon successful authentication, Keycloak redirects the user back to the application's configured `redirect-uri` (`.../login/oauth2/code/keycloak`).
6.  Spring Security handles this callback, validates the token from Keycloak, and creates a standard `SecurityContext`. The user is now authenticated from Spring's perspective.
7.  Spring Security redirects the user to the default success URL, `/Default/sso_login`.
8.  The custom `KeycloakFilter` intercepts this request to `/Default`. It sees that the user is authenticated but does not yet have an AIV session.
9.  The filter calls `DefaultAuthenticateImpl.authenticated()`, which in turn uses `KeycloakAuthImpl` to build a complete AIV user profile, including dynamic permissions from the properties file.
10. `HeaderSecurity` encrypts this profile into a secure payload.
11. The `KeycloakFilter` redirects the user one last time to the AIV frontend URL, appending the encrypted payload as the `e` parameter (e.g., `.../sso_login?e=...`).
12. The AIV frontend loads, decrypts the `e` parameter, and establishes the internal AIV session. The user is now fully logged in.

## 3. Configuration

Configuration is split between the AIV `application.properties` file and the Keycloak Admin Console.

### AIV `application.properties`

The following properties must be configured in your AIV `application.properties` (or `.yml`) file.

1.  **Set the Custom Security Class:**
    This tells AIV to use your Keycloak integration.
    ```properties
    app.securityClass: com.example.KeycloakSSO.KeycloakAuthImpl
    ```

2.  **Configure Spring Security OAuth2 Client:**
    This block tells Spring Security how to connect to your Keycloak realm.
    ```yaml
    spring:
      security:
        oauth2:
          client:
            registration:
              keycloak:
                client-id: Default
                client-secret: [Your-Client-Secret-From-Keycloak]
                authorization-grant-type: authorization_code
                scope: openid,profile,email
                provider: keycloak
                redirect-uri: http://[YOUR_AIV_HOST]:[PORT]/aiv/login/oauth2/code/keycloak
            provider:
              keycloak:
                issuer-uri: http://[YOUR_KEYCLOAK_HOST]:[PORT]/realms/Default
                authorization-uri: http://[YOUR_KEYCLOAK_HOST]:[PORT]/realms/Default/protocol/openid-connect/auth
                token-uri: http://[YOUR_KEYCLOAK_HOST]:[PORT]/realms/Default/protocol/openid-connect/token
                user-info-uri: http://[YOUR_KEYCLOAK_HOST]:[PORT]/realms/Default/protocol/openid-connect/userinfo
                jwks-uri: http://[YOUR_KEYCLOAK_HOST]:[PORT]/realms/Default/protocol/openid-connect/certs
                logout-uri: http://[YOUR_KEYCLOAK_HOST]:[PORT]/realms/Default/protocol/openid-connect/logout
    ```

3.  **Configure Keycloak Admin URL:**
    This tells your `KeycloakAuthImpl` where to send Admin API requests.
    ```properties
    keycloaks:
      url: http://[YOUR_KEYCLOAK_HOST]:[PORT]/
    ```

This is application.properties file for the reference:

<details>
<summary><strong>Click</strong> to view a complete example <code>application.yml</code> file</summary>

```yaml
server:
  compression:
    enabled: true
    mime-types: application/json, text/html, text/xml, text/plain,text/css, text/javascript, application/javascript, application/octet-stream
    min-response-size: 1024
  servlet:
    context-path: /aiv
  port: ${aiv_port}

spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: Default
            client-secret: mlqYrlT2UBmKp2dc2Mchlzi5xFnF35lJ
            authorization-grant-type: authorization_code
            scope: openid,profile,email
            provider: keycloak
            redirect-uri: http://192.168.31.65:8087/aiv/login/oauth2/code/keycloak
        provider:
          keycloak:
            issuer-uri: http://192.168.31.65:8380/realms/Default
            # The following URIs are often discovered automatically from the issuer-uri
            authorization-uri: http://192.168.31.65:8380/realms/Default/protocol/openid-connect/auth
            token-uri: http://192.168.31.65:8380/realms/Default/protocol/openid-connect/token
            user-info-uri: http://192.168.31.65:8380/realms/Default/protocol/openid-connect/userinfo
            jwks-uri: http://192.168.31.65:8380/realms/Default/protocol/openid-connect/certs
            logout-uri: http://192.168.31.65:8380/realms/Default/protocol/openid-connect/logout
            user-name-attribute: preferred_username
  autoconfigure:
    exclude: org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration
  resources:
    static-locations: classpath:/static/,file:///${aiv_base}/repository/images/
  jackson:
    serialization:
      WRITE_DATES_AS_TIMESTAMPS: false
    time-zone: UTC
  datasource:
    url: ${aiv_db_url} # database for aiv schema
    username: ${aiv_db_user}
    password: ${aiv_db_password} 
    driverClassName: org.postgresql.Driver
  datasource1:
    url: ${security_db_url} # database for security schema
    username: ${security_db_user}
    password: ${security_db_password} 
    driverClassName: org.postgresql.Driver
  mvc:
    pathmatch:
      matching-strategy: ANT_PATH_MATCHER
  jpa:
    hibernate: 
      ddl-auto: update
  liquibase:
   aiv:
     enabled: true
     change-log: classpath:db/changelog/db.changelog-aiv.sql
   security:
     enabled: true
     change-log: classpath:db/changelog/db.changelog-security.sql
  kafka:
    bootstrap-servers: localhost:9092
    consumer:
      group-id: task-consumer-group
      auto-offset-reset: earliest
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: com.aiv.cluster.MapDeserializer
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: com.aiv.cluster.MapSerializer

#For JNDI Datasources
datasources:
  dslist[0]: '{"jndi-name":"jdbc/ActiveIDB","driver-class-name":"org.postgresql.Driver","url":"${aiv_db_url}","username":"${aiv_db_user}","password":"${aiv_db_password}"}'

app:
  gatewayApp: http://192.168.31.65:8087/aiv
  gatewayRedirectURL: http://192.168.31.65:8087/aiv/{deptCode}/sso_login
  slatKey: 0123456789abcdef
  ivspec: fedcba9876543210
  imgLocation: ${aiv_base}/repository/images/
  appLocation: ${aiv_base}/repository/APP/
  repositoryLocation: ${aiv_base}/repository
  logDir: ${aiv_base}/logs
  deliveryLocation: ${aiv_base}/repository/delivery
  database: postgresql
  securityClass: com.example.KeycloakSSO.KeycloakAuthImpl
  isJira: false
  noofreports: 10
  task:
    kafka:
      retention.ms: 60000
      topic:
        topicName: task-topic
        partitions: 2
        replication-factor:  1
    manager:
      mode: single

embed:
  ekey: ActiveInteigence
  tokenKey: H0WWWrNDCCoVKVPXMSei9/+rDJcLbgkEOXhayw790lY=
  iscustomtoken: false
  
logging:
  level:
    liquibase: OFF
  
aiv-internalToken: ActiveIntelligence
management.metrics.mongo.command.enabled: false
management.metrics.mongo.connectionpool.enabled: false

keycloaks:
  users_url: http://192.168.31.65:8380/{user}/realms/{dept}/users
  roles_url: http://192.168.31.65:8380/{user}/realms/{dept}/roles
  url: http://192.168.31.65:8380/
```
</details>


### Keycloak Console Setup

The following steps must be performed in the Keycloak Admin Console to prepare for this integration.

1.  **Create a Realm:**
    *   From the `master` realm, create a new realm. For this guide, we'll assume it's named `Default`.

2.  **Create a Client:**
    *   Navigate to the `Default` realm.
    *   Go to `Clients` and click `Create client`.
    *   **Client ID:** `Default` (must match `client-id` in your properties).
    *   **Client protocol:** `openid-connect`.
    *   On the next screen, configure the client:
        *   **Access Type:** `confidential`. This is critical for server-side applications.
        *   **Valid Redirect URIs:** Add the redirect URI from your properties file (e.g., `http://192.168.31.65:8087/aiv/login/oauth2/code/keycloak`).
        *   **Valid Post Logout Redirect URIs:** Add the base URL of your AIV application (e.g., `http://192.168.31.65:8087/aiv`).
        *   Save the client.

3.  **Get Client Secret:**
    *   After saving, go to the `Credentials` tab of your new client.
    *   Copy the `Secret` value and paste it into the `client-secret` field in your `application.properties`.

4.  **Configure Service Account Roles (Crucial):**
    *   Go to the `Service accounts roles` tab for your client.
    *   Click `Assign role`.
    *   From the "Filter by clients" dropdown, select `realm-management`.
    *   Assign the following roles to the service account:
        *   `realm-admin` (or `manage-users`, `view-users`, `manage-roles`, `view-roles` on newer Keycloak versions).
    *   This gives your AIV backend the permission to call the Keycloak Admin API.

5.  **Create Application Roles:**
    *   Navigate to `Realm Roles`.
    *   Click `Create Role`.
    *   Create a role named `admin`.
    *   Create another role named `default-user`.
    *   (Optional) Go to the `Attributes` tab for each role and add a `Key` of `email` with a corresponding `Value` (e.g., `admins@aivhub.com`).

6.  **Create a Test User:**
    *   Navigate to `Users` and click `Create user`.
    *   Set a `Username` (e.g., `testuser`).
    *   Go to the `Credentials` tab for the new user, set a permanent password.
    *   Go to the `Role mapping` tab and assign the `default-user` role.

## 4. Component Breakdown

*   **`KeycloakController.java`**: Handles the OIDC-compliant logout flow by redirecting the user to Keycloak's logout endpoint. It also intercepts AIV's internal `/v5/api/logout` call to ensure SSO logout is triggered.
*   **`KeycloakFilter.java`**: A critical security component. Its primary job is to intercept a successful login from Spring Security and trigger the creation of the AIV-specific session by calling `DefaultAuthenticateImpl`. It also handles the validation and extension of the internal AIV JWT for subsequent API calls.
*   **`KeycloakAuthImpl.java`**: The implementation of `IAuthentication`. It acts as a client for the Keycloak Admin API, fetching and transforming user and role data into the format AIV expects.
*   **`CommonUtility.java`**: Provides helper methods, most importantly `getMasterRealmToken()`, which retrieves the admin access token needed by `KeycloakAuthImpl` to communicate with Keycloak.
*   **`SecurityConfig.java`**: The main Spring Security configuration class. It enables `oauth2Login`, configures the redirect URLs, and sets up the custom user service.
*   **`CustomOAuth2UserService.java`**: Extends the default service to ensure all claims from the Keycloak token are available to the application.

## 5. Deployment and Usage

### Step 1: Build the JAR File

Open a terminal in the root directory of this project and run the Maven command:
```bash
mvn verify
```
This will create the JAR file in the `target/` folder.

### Step 2: Place the JAR File in AIV Docker

1.  **Remove Default Security:** Navigate to `docker-aiv/config/drivers/` and **remove** the existing `security-postgres-2.0.0.jar`.
2.  **Add Custom Security:** Copy your newly compiled JAR file into the `docker-aiv/config/drivers/` folder.

### Step 3: Configure AIV

Ensure your main AIV `application.properties` file (located at `docker-aiv/repository/econfig/`) contains the correct `app.securityClass` and `spring.security.oauth2` configurations as described in Section 3.

### Step 4: Run the Application
```bash
docker-compose up
```

### Step 5: Log In

1.  Open your browser and navigate to `http://[YOUR_AIV_HOST]:[PORT]/aiv/Default`.
2.  You will be automatically redirected to the Keycloak login page.
3.  Enter the credentials for a user you created in Keycloak (e.g., `testuser`).
4.  After successful authentication, you will be redirected back into the AIV application, fully logged in.