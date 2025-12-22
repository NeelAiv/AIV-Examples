# AIV SAML SSO Integration with Okta

## 1. Overview

This project is a Spring Boot security module designed to integrate the AIV platform with **Okta**, a leading cloud-based Identity and Access Management (IAM) solution.

The module acts as a bridge, translating Okta's SAML assertions into the format AIV's backend expects, and manages the internal AIV session after a successful SSO login. It also integrates with Okta's REST API to retrieve user information for administrative operations.

### Key Features of this Implementation

*   **Implements `IAuthentication`:** Seamlessly integrates with the AIV security framework by providing the `SamlAuthenticationImpl2` class, which acts as an adapter between AIV and Okta's SAML assertions and REST API.
*   **Okta as the Central User Store:** All users are managed directly within Okta, eliminating the need for local user tables or files. User data is retrieved via Okta's REST API when needed.
*   **Standard SAML 2.0 Flow:** User authentication is handled via a secure SAML 2.0 redirect flow to the Okta login page, providing a true single sign-on experience.
*   **JWT for Internal AIV Sessions:** After a successful SSO login, a separate, internal JSON Web Token (JWT) is generated to manage the user's session within AIV for API calls, with token generation and extension capabilities.
*   **Spring Security SAML2 Support:** Leverages Spring Security's built-in SAML 2.0 support for handling the authentication flow, while custom filters and handlers manage the AIV-specific session creation.

## 2. How It Works

This module replaces AIV's default security with a modern SAML 2.0 authentication flow.

### The `IAuthentication` Implementation: `SamlAuthenticationImpl2.java`

This class is the **adapter** or **bridge** between AIV and Okta. Unlike password-based authentication systems, it does **not** handle password validation directly. Its primary responsibilities are:

*   **Data Fetching:** When AIV needs a list of users or user details (e.g., for the admin panel), methods like `getAllUsers()` and `getUserByName()` are called. They make secure, authenticated REST API calls to Okta using the Okta Admin API token to retrieve this data.
*   **Data Transformation:** Okta's API returns data in its own format. `SamlAuthenticationImpl2` contains transformation methods (e.g., `buildFullAivUserProfile`) that convert this raw data into the exact JSON structure that the AIV frontend expects, preventing UI errors.
*   **Token Management:** The `authenticate()` method generates and validates JWT tokens for internal AIV session management. It does not validate passwords, as authentication is handled by Okta via SAML.
*   **User Provisioning:** When a new user logs in for the first time via SAML, the system automatically creates the necessary home folders and user profile structures within AIV.

### Data Source: Okta Server

All user data is stored and managed within the Okta server. This provides a central, secure, and feature-rich platform for identity management.

*   **Users:** All application users are created and managed in Okta's user directory.
*   **Roles:** Application-specific roles are managed within AIV, with a default "Administrator" role assigned to all SAML-authenticated users. Fine-grained permissions are defined in the `user_default.properties` file.
*   **Permissions:** The fine-grained permissions for AIV (e.g., `dashboardOption`, `reportOption`) are not stored in Okta directly. Instead, they are defined in the `user_default.properties` file and are dynamically applied by the `SamlAuthenticationImpl2` class.

### Authentication and Session Flow

1.  A user navigates to an AIV entry point (e.g., `http://[YOUR_AIV_HOST]:[PORT]/aiv`).
2.  The `SamlInitiationFilter` intercepts the request and detects that the user is not authenticated.
3.  The user's browser is redirected to the **Okta SAML login page** via Spring Security's SAML 2.0 support.
4.  The user enters their credentials **at Okta**.
5.  Upon successful authentication, Okta generates a SAML assertion and redirects the user back to the application's configured Assertion Consumer Service (ACS) URL (`/login/saml2/sso/okta`).
6.  Spring Security handles the SAML response, validates the assertion, and creates a standard `SecurityContext`. The user is now authenticated from Spring's perspective.
7.  The custom `SamlAuthenticationSuccessHandler2` intercepts the successful authentication.
8.  The handler extracts user attributes (username, email, firstName, lastName) from the SAML assertion using configurable attribute mappings.
9.  The handler calls `SamlAuthenticationImpl2.authenticate()` to generate an internal AIV JWT token and build a complete AIV user profile.
10. `HeaderSecurity` encrypts this profile into a secure payload.
11. The handler redirects the user to the AIV frontend URL, appending the encrypted payload as the `e` parameter (e.g., `.../sso_login?e=...`).
12. The AIV frontend loads, decrypts the `e` parameter, and establishes the internal AIV session. The user is now fully logged in.
13. For subsequent API calls, the `SamlInitiationFilter` validates the JWT token from the request headers to ensure the session is still valid.

## 3. Configuration

Configuration is split between the AIV `application.properties` file and the Okta Admin Console.

### AIV `application.properties`

The following properties must be configured in your AIV `application.properties` (or `.yml`) file.

1.  **Set the Custom Security Class:**
    This tells AIV to use your SAML with Okta integration.
    ```properties
    app.securityClass: com.example.SAMLwOkta.SamlAuthenticationImpl2
    ```

2.  **Configure Okta API Credentials:**
    This tells your `SamlAuthenticationImpl2` where to send Admin API requests and how to authenticate.
    ```yaml
    okta:
      api:
        token: [YOUR_OKTA_API_TOKEN]
        domain: [YOUR_OKTA_DOMAIN].okta.com
    ```

3.  **Configure SAML Attribute Mappings:**
    This maps SAML assertion attributes to AIV user profile fields.
    ```yaml
    saml:
      attribute:
        mapping:
          userName: "username"
          firstname: "firstName"
          lastname: "lastName"
          email: "email"
          department: "department"
    ```

4.  **Configure AIV SSO Redirect URLs:**
    This tells the application where to redirect users after successful authentication and logout.
    ```yaml
    aiv:
      sso:
        test-redirect-base-url: "http://[YOUR_AIV_HOST]:[PORT]/aiv"
        post-logout-redirect-uri: "http://[YOUR_AIV_HOST]:[PORT]/aiv/"
    ```

5.  **Configure Spring Security SAML2:**
    This configures the SAML 2.0 relying party registration with Okta.
    ```yaml
    spring:
      security:
        saml2:
          relyingparty:
            registration:
              okta:
                entity-id: aiv-saml-sp
                signing:
                  credentials:
                    - private-key-location: "classpath:sp-private-key.pem"
                      certificate-location: "classpath:sp-certificate.pem"
                assertingparty:
                  metadata-uri: "https://[YOUR_OKTA_DOMAIN].okta.com/app/[APP_ID]/sso/saml/metadata"
    ```

<details>
<summary><strong>Click</strong> to view a complete example <code>application.yml</code> file</summary>

```yaml
okta:
  api:
    token: [YOUR_OKTA_API_TOKEN]
    domain: [YOUR_OKTA_DOMAIN].okta.com

aiv:
  sso:
    test-redirect-base-url: "http://localhost:8080/aiv"
    post-logout-redirect-uri: "http://localhost:8080/aiv/"

saml:
  attribute:
    mapping:
      userName: "username"
      firstname: "firstName"
      lastname: "lastName"
      email: "email"
      department: "department"

spring:
  security:
    saml2:
      relyingparty:
        registration:
          okta:
            entity-id: aiv-saml-sp
            signing:
              credentials:
                - private-key-location: "classpath:sp-private-key.pem"
                  certificate-location: "classpath:sp-certificate.pem"
            assertingparty:
              metadata-uri: "https://[YOUR_OKTA_DOMAIN].okta.com/app/[APP_ID]/sso/saml/metadata"

app:
  securityClass: com.example.SAMLwOkta.SamlAuthenticationImpl2
```

</details>

### Okta Console Setup

The following steps must be performed in the Okta Admin Console to prepare for this integration.

1.  **Create a SAML Application:**
    *   Log in to your Okta Admin Console.
    *   Navigate to **Applications** > **Applications**.
    *   Click **Create App Integration**.
    *   Select **SAML 2.0** as the sign-in method.
    *   Click **Next**.

2.  **Configure General Settings:**
    *   **App name:** Enter a descriptive name (e.g., "AIV Application").
    *   Click **Next**.

3.  **Configure SAML Settings:**
    *   **Single sign-on URL:** `http://[YOUR_AIV_HOST]:[PORT]/aiv-sso/login/saml2/sso/okta`
    *   **Audience URI (SP Entity ID):** `aiv-saml-sp` (must match `entity-id` in your properties)
    *   **Default RelayState:** (Leave blank or set to your AIV base URL)
    *   **Name ID format:** `EmailAddress` or `Unspecified`
    *   **Application username:** `Email` or `Okta username`
    *   **Attribute statements:** Configure the following:
        *   `username` → `user.email` or `user.login`
        *   `firstName` → `user.firstName`
        *   `lastName` → `user.lastName`
        *   `email` → `user.email`
    *   Click **Next**.

4.  **Configure Feedback:**
    *   Select **I'm an Okta customer adding an internal app**.
    *   Click **Finish**.

5.  **Get Application Metadata:**
    *   After creating the app, go to the **Sign On** tab.
    *   Scroll down to find the **SAML 2.0** section.
    *   Copy the **Identity Provider metadata** URL (or download the metadata file).
    *   Use this URL in your `application.yml` as the `metadata-uri` value.

6.  **Generate Service Provider Certificates:**
    *   You need to generate a private key and certificate for the Service Provider (AIV application).
    *   These files should be placed in `src/main/resources/`:
        *   `sp-private-key.pem` - The private key
        *   `sp-certificate.pem` - The public certificate
    *   You can generate these using OpenSSL:
        ```bash
        openssl req -x509 -newkey rsa:2048 -keyout sp-private-key.pem -out sp-certificate.pem -days 365 -nodes
        ```

7.  **Upload Service Provider Certificate to Okta:**
    *   In your Okta SAML application settings, go to the **Sign On** tab.
    *   Scroll to **SAML Signing Certificates**.
    *   Click **Add Certificate** and upload your `sp-certificate.pem` file.

8.  **Create an Okta API Token:**
    *   In Okta Admin Console, go to **Security** > **API**.
    *   Click **Tokens** tab, then **Create Token**.
    *   Give it a name (e.g., "AIV Integration Token").
    *   Copy the token value immediately (it won't be shown again).
    *   Use this token in your `application.yml` as the `okta.api.token` value.

9.  **Assign Users:**
    *   Go to your SAML application.
    *   Click the **Assignments** tab.
    *   Click **Assign** and select the users or groups that should have access to AIV.

## 4. Component Breakdown

*   **`SamlAuthenticationImpl2.java`**: The implementation of `IAuthentication`. It acts as a client for the Okta Admin API, fetching and transforming user data into the format AIV expects. It also handles JWT token generation and validation for internal AIV sessions.
*   **`SamlInitiationFilter.java`**: A critical security component. Its primary job is to intercept unauthenticated requests to AIV entry points and redirect them to the SAML authentication flow. It also handles JWT token validation and extension for subsequent API calls.
*   **`SamlAuthenticationSuccessHandler2.java`**: Handles successful SAML authentication. It extracts user attributes from the SAML assertion, calls `SamlAuthenticationImpl2` to create the AIV session, and redirects the user to the AIV frontend with an encrypted payload.
*   **`OktaService.java`**: A service class that provides methods to interact with Okta's REST API. It handles fetching user lists and individual user details using the Okta Admin API token.
*   **`Saml2RelyingPartyConfiguration.java`**: Configures the SAML 2.0 relying party registration repository. It loads the Service Provider certificates and configures the connection to Okta's Identity Provider metadata.
*   **`SecurityConfig.java`**: The main Spring Security configuration class. It enables SAML 2.0 login, configures the filter chain, and sets up the custom authentication success handler.
*   **`JwtTokenUtil.java`**: A utility class for all JWT-related operations, including token generation, validation, and expiration extension.

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

Ensure your main AIV `application.properties` file (located at `docker-aiv/repository/econfig/`) contains the correct `app.securityClass` and SAML/Okta configurations as described in Section 3.

### Step 4: Ensure Certificates Are Available

Make sure the Service Provider certificates (`sp-private-key.pem` and `sp-certificate.pem`) are included in your JAR file's classpath (in `src/main/resources/`) or are accessible at runtime.

### Step 5: Run the Application

```bash
docker-compose up
```

### Step 6: Log In

1.  Open your browser and navigate to `http://[YOUR_AIV_HOST]:[PORT]/aiv/`.
2.  You will be automatically redirected to the Okta login page.
3.  Enter the credentials for a user assigned to your SAML application in Okta.
4.  After successful authentication, you will be redirected back into the AIV application, fully logged in.
