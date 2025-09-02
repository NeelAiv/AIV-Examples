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

The user store is managed by three files located in `src/main/resources/data/`:

1.  **`users.csv`**: The master user list. It contains user credentials, their assigned `department`, status, and base permissions. **This file is the source of truth for authentication.**
2.  **`roles.csv`**: Defines all available roles and the specific permissions (e.g., `reportOption`, `adminOption`) granted by each role. Roles are also scoped by `department`.
3.  **`user_roles.csv`**: A simple mapping file that assigns one or more roles to each user.

### Authentication and Session Flow

1.  A user submits their credentials (e.g., `Default::Admin` and a password) via the `login.html` page.
2.  The `AuthController` receives the request, parses the `department` and `username`, and calls `CsvAuthenticationImpl.authenticate()`.
3.  `CsvAuthenticationImpl` verifies the credentials against the data from `users.csv`.
4.  Upon success, the `AuthController` uses `JwtTokenUtil` to generates a token.
5.  The user is logged in and can now access the application.
6.  For subsequent API calls, the `CsvAuthFilter` intercepts the request, validates the JWT.

## 3. Configuration

### `application.properties`

These properties tell the `CsvAuthenticationImpl` class where to find its data files.

```properties
# Paths to the CSV data files relative to the resources folder
# You can customize the paths according to your requirements
sso.csv.users-file=classpath:data/users.csv
sso.csv.roles-file=classpath:data/roles.csv
sso.csv.user-roles-file=classpath:data/user_roles.csv

# Path to the user defaults properties file
sso.user-defaults-path=classpath:user_default.properties
```

### `user_default.properties`

This file provides default permission templates that can be used when creating new users. It allows for defining a baseline set of permissions for different types of users (e.g., an administrator vs. a standard user).

### The `token` File

This file, located at `src/main/resources/token`, contains the Base64 encoded secret key used for signing and validating all JWTs. It is critical for the security of the application.

## 4. Component Breakdown

### `AuthController.java`
Handles all direct authentication actions.
*   **`handleLogin(...)`**: The main endpoint for form-based login. It orchestrates the entire process of parsing credentials, calling the authentication service, generating a token, and redirecting the user.
*   **`authenticateApi(...)`**: An API endpoint for programmatic authentication. It takes credentials as a JSON body and returns a secure payload.


### `PageController.java`
Responsible for serving non-API pages.
*   **`showLoginPage()`**: Simply returns the `login.html` file.

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

## 6. How to Use

1.  Ensure this project is included in your AIV Application.
2.  Populate the `.csv` files with your desired user data.
4.  Build and run the main application. The login and authentication will now be handled by this CSV-based module.