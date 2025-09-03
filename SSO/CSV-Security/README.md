# AIV CSV SSO Authentication

## 1. Overview

This project is a Spring Boot application that overrides standard authentication mechanisms to provide a self-contained login system.

The core functionality is to authenticate users against a set of CSV (Comma-Separated Values) files that act as a simple, file-based database. It handles user login, session management via JSON Web Tokens (JWT), and request filtering to protect application endpoints.

### Key Features of this Implementation

*   **Implements `IAuthentication`:** Seamlessly integrates with the AIV security framework by providing a concrete implementation of the core security interface.

*   **CSV-Based User Store:** User, role, and user-role mapping data are managed in `.csv` files.
*   **Department Scoping:** Users and roles are scoped by a `department`, allowing for multi-tenant-like behavior.
*   **Custom Login Format:** Supports a special login format of `department::username`.
*   **JWT for Sessions:** Uses JWT for stateless session management, with token generation and extension capabilities.
*   **Servlet Filter Security:** A custom filter intercepts incoming requests to ensure the user is authenticated before accessing protected resources.

## 2. How It Works

This module overrides the default database-driven security logic with its own custom flow centered around the `CsvAuthenticationImpl` class.

### The `IAuthentication` Implementation: `CsvAuthenticationImpl.java`

This class is the brain of the module. It implements the `IAuthentication` interface and provides the logic for all security-related operations by reading from the in-memory CSV data.

*   **On Startup:** The application reads the paths to the CSV files from `application.properties` and calls the `loadDataFromCsv()` method. This loads all user and role data into memory for fast access.
*   **Authentication:** When a user logs in, the `authenticate()` method is called. It searches the loaded user data for a matching username, department, and password.
*   **Authorization:** For API requests, the `isAuthorize()` method is called. It validates the JWT sent in the request headers to confirm the user's session is valid.

### Data Source: CSV Files

The user store is managed by three files. The default location is `src/main/resources/data/`, but for easier updates, it is recommended to place them in an external folder.

1.  **`users.csv`**: The master user list. It contains user credentials, their assigned `department`, status, and base permissions. **This file is the source of truth for authentication.**
    *   **Note on User Limits:** Please be aware that the free trial version of AIV supports a maximum of two users with an `Active` status.
2.  **`roles.csv`**: Defines all available roles and the specific permissions (e.g., `reportOption`, `adminOption`) granted by each role. Roles are also scoped by `department`.
3.  **`user_roles.csv`**: A simple mapping file that assigns one or more roles to each user.

To make updates easier without modifying the application code, users should create a `csv_data` folder inside the **AIV Docker’s repository** (`docker-aiv\repository`) folder and place the three CSV files (`users.csv`, `roles.csv`, and `user_roles.csv`) inside it.

This allows administrators to update user or role information simply by replacing the CSV files — without rebuilding or redeploying the application.

The application automatically reads the CSV files from this external folder based on the paths configured in `application.properties`

#### Example CSV File Formats

Below are examples of how each CSV file should be structured.

**`users.csv`**
This file contains all user-specific data, including their credentials and base permissions.

```csv
id,firstName,lastName,userName,status,password,email,homeFolder,backupUserId,managerUserId,dashboardOption,alertsOption,reportOption,mergeReportOption,adhocOption,resourceOption,quickRunOption,mappingOption,messageOption,datasetOption,parameterOption,annotationOption,notificationOption,requestOption,adminOption,scheduleOption,webhookOption,userType,default_dashboard,landing_page,locale,timezone,theme,notification,department,showname,showimage
1,Admin,User,Admin,Active,password,admin@aivhub.com,/Admin,,,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,INT,,Documents/Reports,en,SYSTEM,Default,0,Default,1,1
2,Sarah,Clark,Sclark,Active,sclarkpass,s.clark@aivhub.com,/sclark,,,1,1,2,1,2,1,1,0,1,2,1,1,1,1,0,1,0,INT,,Documents/Reports,en,SYSTEM,Default,0,Default,1,1
3,John,Doe,Jdoe,Inactive,jdoepass,j.doe@aivhub.com,/jdoe,,,1,1,1,1,1,1,1,0,1,1,1,1,1,1,0,1,0,INT,,Documents/Reports,en,SYSTEM,Default,0,Default,1,1
4,Jane,Smith,Jsmith,Inactive,jsmithpass,j.smith@aivhub.com,/jsmith,,,1,0,1,0,0,1,0,0,1,0,0,1,1,0,0,0,0,INT,,Documents/Reports,en,SYSTEM,Default,0,Default,1,1
5,Guest,User,Guest,Inactive,guestpass,guest@aivhub.com,/guest,,,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,INT,,Documents/Reports,en,SYSTEM,Default,0,Default,1,1
```

**`roles.csv`**
This file defines the roles and the specific permissions granted by each role.

```csv
id,name,description,email,dashboardOption,alertsOption,reportOption,mergeReportOption,adhocOption,resourceOption,quickRunOption,mappingOption,messageOption,datasetOption,parameterOption,annotationOption,notificationOption,requestOption,adminOption,scheduleOption,webhookOption,department
1,Administrator,Full access role,admin@aivhub.com,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,Default
2,Data Analyst,"Can create and edit reports, dashboards, and datasets",admin@aivhub.com,2,1,2,1,2,1,1,1,1,2,2,1,1,1,0,2,1,Default
3,Content Editor,"Can create and edit reports and dashboards, but not datasets",admin@aivhub.com,2,1,2,1,1,1,1,0,1,0,1,1,1,1,0,1,0,Default
4,Report Publisher,"Can schedule and publish reports created by others",admin@aivhub.com,1,1,1,0,0,1,0,0,1,0,0,1,1,0,0,2,0,Default
5,Viewer,"Read-only access to view dashboards and reports",admin@aivhub.com,1,0,1,0,0,1,0,0,1,0,0,1,1,0,0,0,0,Default
```

**`user_roles.csv`**
This file maps users to their assigned roles.

```csv
id,userName,roleName
1,Admin,Administrator
2,Sclark,Data Analyst
3,Sclark,Report Publisher
4,Jdoe,Content Editor
5,Jdoe,Viewer
6,Jsmith,Viewer
```

### Authentication and Session Flow

1.  A user submits their credentials (e.g., `Default::Admin` and a password) via the `login.html` page.
2.  The `AuthController` receives the request, parses the `department` and `username`, and calls `CsvAuthenticationImpl.authenticate()`.
3.  `CsvAuthenticationImpl` verifies the credentials against the data from `users.csv`.
4.  Upon success, the `AuthController` uses `JwtTokenUtil` to generates a token.
5.  The user is logged in and can now access the application.
6.  For subsequent API calls, the `CsvAuthFilter` intercepts the request, validates the JWT.

## 3. Configuration

### CSV File Location

There are two ways to configure the location of your `users.csv`, `roles.csv`, and `user_roles.csv` files.

*   **Method 1: Development (Classpath)**
    For local development, you can place the CSV files inside the project's `src/main/resources/data` folder. The application will find them automatically using the default `application.properties` settings within the JAR. This is convenient for testing but is not recommended for production.
    ```properties
    # Default paths for development, pointing to files inside the JAR
    sso.csv.users-file=classpath:data/users.csv
    sso.csv.roles-file=classpath:data/roles.csv
    sso.csv.user-roles-file=classpath:data/user_roles.csv
    ```

*   **Method 2: Production (External File Path) - Recommended**
    For a production environment like Docker, it is best to store the CSV files outside the application JAR. This allows you to update user data without rebuilding the project. You can place the files in a folder like `docker-aiv/repository/csv_data` and then point to them in your AIV's main `application.properties` file. **The deployment instructions in Section 6 use this method.**

### Other Configuration Files

*   **`user_default.properties`**: This file provides default permission templates that can be used when creating new users. It allows for defining a baseline set of permissions for different types of users (e.g., an administrator vs. a standard user).

*   **The `token` File**: This file, located at `src/main/resources/token`, contains the Base64 encoded secret key used for signing and validating all JWTs. It is critical for the security of the application.

## 4. Component Breakdown

### `AuthController.java`
Handles all direct authentication actions.
*   **`handleLogin(...)`**: The main endpoint for form-based login. It orchestrates the entire process of parsing credentials, calling the authentication service, generating a token, and redirecting the user.


### `PageController.java`
Responsible for serving non-API pages and handling user logout.
*   **`showLoginPage()`**: Simply returns the `login.html` file.
*   **`logout(...)`**: Handles the user logout process by invalidating the session and redirecting the user to the login page.

### `CsvAuthFilter.java`
A critical security component that protects endpoints.
*   **`doFilter(...)`**: The main filter method. It checks every incoming request. It ignores public paths (`/login`, `/login-handler`), redirects unauthenticated users from protected entry points, and triggers token extension for API calls.
*   **`handleTokenExtensionForSpecialUrls(...)`**: Contains the logic to check if a token needs to be refreshed and calls the `JwtTokenUtil` to do so.

### `CsvAuthenticationImpl.java`
The implementation of the `IAuthentication` interface; the brain of the CSV logic.
*   **`setApplicationContextAndDatasource(...)`**: This method is called by the framework on startup. It gets the paths to the CSV files from `application.properties` and triggers the initial data load.
*   **`loadDataFromCsv()`**: Reads the `users`, `roles`, and `user_roles` CSV files into in-memory `List<Map<String, String>>` objects for fast access.
*   **`authenticate(...)`**: The primary method for checking a user's credentials against the loaded user data.
*   **`isAuthorize(...)`**: Called by the AIV framework for API requests. It extracts the token from the request headers and uses `JwtTokenUtil.validateToken()` to check its validity.


### `JwtTokenUtil.java`
A utility class for all JWT-related operations.
*   **`generateToken(...)`**: Creates and signs a new JWT. It sets the subject (username), issued-at time, and expiration date.
*   **`validateToken(...)`**: Parses a token and verifies its signature. Returns `true` if valid, `false` if it's malformed, expired, or has an invalid signature.
*   **`extendTokenExpiration(...)`**: Creates a new token with a new expiration date based on an existing, valid token.

## 5. Key `IAuthentication` Method Implementations

This module provides concrete implementations for the methods defined in the `IAuthentication` interface. Below are the most important ones.

<details>
<summary><strong>Click</strong> to view key method descriptions</summary>

*   **`authenticate(Map<String, Object> map)`**
    *   **Implementation:** This is the core login method. It filters the in-memory list of users based on the `userName` and `deptCode` provided in the map. It then performs a case-sensitive check on the `password` and verifies the user's `status` is "Active".
    *   **Returns:** A `Map` of the user's details from `users.csv` on success, or `null` on failure.

*   **`isAuthorize(Map<String, Object> headers)`**
    *   **Implementation:** This method is called for API requests. It extracts the JWT from the `x-xsrftoken` header and uses `JwtTokenUtil.validateToken()` to verify its signature and expiration.
    *   **Returns:** `true` if the token is valid, `false` otherwise.

*   **`getUserRoleFeatures(String userName, String deptCode)`**
    *   **Implementation:** This method calculates a user's effective permissions. It first retrieves the user's base permissions from their record in `users.csv`. Then, it finds all roles assigned to that user from `user_roles.csv` and aggregates the permissions from `roles.csv`, always taking the highest permission level (`0`, `1`, or `2`) for each feature.
    *   **Returns:** A `Map` containing the final, aggregated set of permissions for the user.

*   **`getAllUsers(String deptCode, ...)`**, **`getAllRoles(String deptCode, ...)`**, **`getAllDepartments(...)`**
    *   **Implementation:** These methods simply return the in-memory lists of data loaded from their respective CSV files, filtering by department where applicable.

*   **`CreateEditUser(...)`**, **`deleteUserById(...)`**, **`updateRolesForUser(...)`**, etc.
    *   **Implementation:** To enable user management, you would need to add logic to these methods to modify the CSV files on disk and trigger a data reload.

</details>

## 6. Deployment and Usage

Follow these steps to deploy and use the CSV authentication module with your AIV application.

### Step 1: Build the JAR File

Before deploying, you need to build the project to generate the executable JAR file. Open a terminal in the root directory of this project and run the following Maven command:

```bash
mvn verify
```

Once the build is successful, you will find the generated `.jar` file inside the `target/` folder of the project.

### Step 2: Place CSV and JAR Files in AIV Docker

1.  **Remove the Default Security Driver:** Navigate to the `docker-aiv/config/drivers/` folder. To prevent conflicts, you **must** remove or move the existing `security-postgres-2.0.0.jar` file out of this directory. Your custom CSV authentication JAR will replace it.

2.  **Add the Custom Security JAR:** Copy the compiled `.jar` file (from the `target/` folder in Step 1) into the same `docker-aiv/config/drivers/` folder.

3.  **Create a Data Folder:** Create a new folder named `csv_data` inside your `docker-aiv/repository/` directory.

4.  **Add Your CSV Files:** Place your `users.csv`, `roles.csv`, and `user_roles.csv` files inside the `csv_data` folder you just created.

### Step 3: Configure AIV

Navigate to `docker-aiv/repository/econfig/` and open the `application.properties` file. You need to make the following changes:

1.  **Set the Custom Security Class:**
    Find the `app.securityClass` property and change its value to point to the implementation in this project.
    ```properties
    # Change this line
    app.securityClass: com.security.services.SimpleAuthImpl
    # To this
    app.securityClass: com.example.AIVcsv.security.CsvAuthenticationImpl
    ```

2.  **Enable SSO Redirect:**
    Ensure the `ssoredirect` property under the `app` section is set to `true`.
    ```properties
    app.ssoredirect: true
    ```

3.  **Add CSV File Paths:**
    Add the following block to the end of the file. This tells the application to load the CSV files from the external `csv_data` directory you created.
    ```properties
    sso:
      csv:
        users-file: file:/opt/repository/csv_data/users.csv
        roles-file: file:/opt/repository/csv_data/roles.csv
        user-roles-file: file:/opt/repository/csv_data/user_roles.csv
      user-defaults-path: classpath:user_default.properties

### Step 4: Run the Application

Navigate to your main `docker-aiv` directory in your terminal and run the application using Docker Compose.
```bash
docker-compose up
```

### Step 5: Log In

Once the application is running, open your web browser and go to `http://localhost:8080/aiv`. You will be redirected to the custom login page.



Enter your credentials in the following format:
*   **Username:** `department::username` (e.g., `Default::Admin`)
*   **Password:** The password for that user.

After clicking **Log In**, you will be authenticated and redirected to the AIV application. When you log out of AIV, you will be returned to this custom login page.
