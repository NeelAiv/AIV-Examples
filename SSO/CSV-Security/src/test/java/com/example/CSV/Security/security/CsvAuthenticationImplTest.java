package com.example.CSV.Security.security;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.FileSystemResource;

import javax.sql.DataSource;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("CsvAuthenticationImpl Tests")
class CsvAuthenticationImplTest {

    private CsvAuthenticationImpl csvAuthentication;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private Environment environment;

    @TempDir
    Path tempDir;

    private static final String USERS_CSV = "id,firstName,lastName,userName,status,password,department,email,homeFolder,adminOption,reportOption\n" +
            "1,Admin,User,Admin,Active,password,Default,admin@aiv.com,/Admin,2,2\n" +
            "2,Demo,User,Demo,Active,demopass,Default,demo@aiv.com,/demo,0,2\n" +
            "3,SalesUser,User,SalesUser,Active,salespass,Sales,sales@aiv.com,/SalesUser,2,2\n" +
            "4,InactiveUser,User,InactiveUser,Inactive,inactivepass,Default,inactive@aiv.com,/InactiveUser,0,0";

    private static final String ROLES_CSV = "id,name,department,adminOption,reportOption\n" +
            "1,Administrator,Default,2,2\n" +
            "2,Viewer,Default,0,1\n" +
            "3,SalesAdmin,Sales,2,2";

    private static final String USER_ROLES_CSV = "id,userName,roleName\n" +
            "1,Admin,Administrator\n" +
            "2,Demo,Viewer\n" +
            "3,SalesUser,SalesAdmin";

    private static final String USER_DEFAULTS = "admin_adminOption=2\n" +
            "admin_reportOption=2\n" +
            "admin_userType=INT\n" +
            "demo_adminOption=0\n" +
            "demo_reportOption=2\n" +
            "demo_userType=INT";

    @BeforeEach
    void setUp() throws IOException {

        Path usersFile = tempDir.resolve("users.csv");
        Path rolesFile = tempDir.resolve("roles.csv");
        Path userRolesFile = tempDir.resolve("user_roles.csv");
        Path userDefaultsFile = tempDir.resolve("user_default.properties");

        Files.writeString(usersFile, USERS_CSV);
        Files.writeString(rolesFile, ROLES_CSV);
        Files.writeString(userRolesFile, USER_ROLES_CSV);
        Files.writeString(userDefaultsFile, USER_DEFAULTS);

        csvAuthentication = new CsvAuthenticationImpl();

        when(environment.getProperty("sso.csv.users-file")).thenReturn(usersFile.toUri().toString());
        when(environment.getProperty("sso.csv.roles-file")).thenReturn(rolesFile.toUri().toString());
        when(environment.getProperty("sso.csv.user-roles-file")).thenReturn(userRolesFile.toUri().toString());
        when(environment.getProperty("sso.user-defaults-path")).thenReturn(userDefaultsFile.toUri().toString());

        when(applicationContext.getEnvironment()).thenReturn(environment);

        when(applicationContext.getResource(anyString())).thenAnswer(invocation -> {
            String path = invocation.getArgument(0, String.class);
            return new FileSystemResource(new File(path.replace("file:", "")));
        });

        csvAuthentication.setApplicationContextAndDatasource(applicationContext);
    }

    @AfterEach
    void tearDown() throws Exception {
        Field instanceField = CsvAuthenticationImpl.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
    }

    @Nested
    @DisplayName("Authentication Logic")
    class AuthenticationTests {
        @Test
        @DisplayName("should authenticate user with correct credentials")
        void authenticate_success() {
            Map<String, Object> credentials = Map.of("userName", "Admin", "password", "password", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.authenticate(credentials);
            assertNotNull(result);
            assertEquals("Admin", result.get("userName"));
        }

        @Test
        @DisplayName("should fail authentication with incorrect password")
        void authenticate_wrongPassword() {
            Map<String, Object> credentials = Map.of("userName", "Admin", "password", "wrong", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.authenticate(credentials);
            assertNull(result);
        }

        @Test
        @DisplayName("should fail authentication for non-existent user")
        void authenticate_userNotFound() {
            Map<String, Object> credentials = Map.of("userName", "Unknown", "password", "password", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.authenticate(credentials);
            assertNull(result);
        }

        @Test
        @DisplayName("should fail authentication for user in wrong department")
        void authenticate_wrongDepartment() {
            Map<String, Object> credentials = Map.of("userName", "SalesUser", "password", "salespass", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.authenticate(credentials);
            assertNull(result);
        }

        @Test
        @DisplayName("should fail authentication for inactive user")
        void authenticate_inactiveUser() {
            Map<String, Object> credentials = Map.of("userName", "InactiveUser", "password", "inactivepass", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.authenticate(credentials);
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Embed Authentication")
    class EmbedAuthenticationTests {
        @Test
        @DisplayName("should succeed for embed authenticate with valid data")
        void embedAuthenticate_success() {
            Map<String, Object> data = Map.of("userName", "Demo", "password", "demopass", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.embedAuthenticate(null, null, data);
            assertNotNull(result);
            assertEquals("Demo", result.get("owner"));
            assertEquals("Demo", result.get("userName"));
        }

        @Test
        @DisplayName("should fail for embed authenticate with missing username")
        void embedAuthenticate_missingUsername() {
            Map<String, Object> data = Map.of("password", "demopass", "deptCode", "Default");
            Map<String, Object> result = csvAuthentication.embedAuthenticate(null, null, data);
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Data Retrieval")
    class DataRetrievalTests {
        @Test
        @DisplayName("should return all unique departments")
        void getAllDepartments_success() {
            List<Map<String, Object>> departments = csvAuthentication.getAllDepartments("Default", null);
            assertEquals(2, departments.size());
            assertTrue(departments.stream().anyMatch(d -> d.get("deptcode").equals("Default")));
            assertTrue(departments.stream().anyMatch(d -> d.get("deptcode").equals("Sales")));
        }

        @Test
        @DisplayName("should return user by name and department")
        void getUserByName_success() {
            Map<String, Object> user = csvAuthentication.getUserByName("SalesUser", "Sales", null);
            assertNotNull(user);
            assertEquals("SalesUser", user.get("userName"));
        }

        @Test
        @DisplayName("should return null for non-existent user")
        void getUserByName_notFound() {
            Map<String, Object> user = csvAuthentication.getUserByName("Unknown", "Default", null);
            assertNull(user);
        }

        @Test
        @DisplayName("should return role by name and department")
        void getRoleByName_success() {
            Map<String, Object> role = csvAuthentication.getRoleByName("Administrator", "Default", null);
            assertNotNull(role);
            assertEquals("Administrator", role.get("name"));
        }

        @Test
        @DisplayName("should return null for non-existent role")
        void getRoleByName_notFound() {
            Map<String, Object> role = csvAuthentication.getRoleByName("UnknownRole", "Default", null);
            assertNull(role);
        }

        @Test
        @DisplayName("should return all users")
        void getAllUsers_success() {
            List<Map<String, Object>> users = csvAuthentication.getAllUsers("Default", null);
            assertEquals(4, users.size());
        }

        @Test
        @DisplayName("should return all roles")
        void getAllRoles_success() {
            List<Map<String, Object>> roles = csvAuthentication.getAllRoles("Default", null);
            assertEquals(3, roles.size());
        }

        @Test
        @DisplayName("should return departments with their respective admin users")
        void getAlldepartmentsWithAdmin_success() {
            List<Map<String, Object>> result = csvAuthentication.getAlldepartmentsWithAdmin("owner", "Default");
            assertEquals(2, result.size());
            Map<String, Object> defaultDept = result.stream().filter(d -> d.get("deptCode").equals("Default")).findFirst().orElseThrow();
            assertEquals("Admin", defaultDept.get("userName"));
            Map<String, Object> salesDept = result.stream().filter(d -> d.get("deptCode").equals("Sales")).findFirst().orElseThrow();
            assertEquals("SalesUser", salesDept.get("userName"));
        }

        @Test
        @DisplayName("should return users for a specific role")
        void selectUsersOfRole_success() {
            List<Map<String, Object>> users = csvAuthentication.selectUsersOfRole("Viewer", "Default");
            assertEquals(1, users.size());
            assertEquals("Demo", users.get(0).get("userName"));
        }

        @Test
        @DisplayName("should return roles for a specific user")
        void selectRolesOfUser_success() {
            List<Map<String, Object>> roles = csvAuthentication.selectRolesOfUser("SalesUser", "Sales");
            assertEquals(1, roles.size());
            assertEquals("SalesAdmin", roles.get(0).get("name"));
        }
    }

    @Nested
    @DisplayName("Feature and Role Aggregation")
    class FeatureAggregationTests {

        @Test
        @DisplayName("should correctly merge user and role features for Admin")
        void getUserRoleFeatures_forAdmin() {
            Map<String, Object> features = csvAuthentication.getUserRoleFeatures("Admin", "Default");
            assertNotNull(features);
            assertEquals("2", features.get("adminOption"));
            assertEquals("2", features.get("reportOption"));
            assertEquals("admin@aiv.com", features.get("email"));
            assertFalse(features.containsKey("password"));
        }

        @Test
        @DisplayName("should correctly merge user and role features for Viewer")
        void getUserRoleFeatures_forViewer() {
            Map<String, Object> features = csvAuthentication.getUserRoleFeatures("Demo", "Default");
            assertNotNull(features);
            assertEquals("0", features.get("adminOption"));
            assertEquals("2", features.get("reportOption")); // Higher value (2 from user) is kept over role's value (1)
        }

        @Test
        @DisplayName("should return empty map for user not found in getUserRoleFeatures")
        void getUserRoleFeatures_notFound() {
            Map<String, Object> features = csvAuthentication.getUserRoleFeatures("Unknown", "Default");
            assertNotNull(features);
            assertTrue(features.isEmpty());
        }

        @Test
        @DisplayName("should generate final payload with all properties for getAuthAfterTimeUser")
        void getAuthAfterTimeUser_success() {
            Map<String, Object> payload = csvAuthentication.getAuthAfterTimeUser("Admin", "Default", "trace123");
            assertNotNull(payload);
            assertEquals("Admin", payload.get("userName"));
            assertEquals("Administrator", payload.get("roles"));
            assertEquals("2", payload.get("adminOption"));
            assertEquals("/Admin", payload.get("homeFolder"));
        }

        @Test
        @DisplayName("should return null from getAuthAfterTimeUser if user does not exist")
        void getAuthAfterTimeUser_userNotFound() {
            Map<String, Object> payload = csvAuthentication.getAuthAfterTimeUser("Unknown", "Default", "trace123");
            assertNull(payload);
        }
    }

    @Nested
    @DisplayName("Authorization and Existence Checks")
    class AuthorizationAndExistenceTests {
        @Test
        @DisplayName("should return true if user exists")
        void isUserExists_true() {
            assertTrue(csvAuthentication.isUserExists("Admin", "Default"));
        }

        @Test
        @DisplayName("should return false if user does not exist")
        void isUserExists_false() {
            assertFalse(csvAuthentication.isUserExists("Unknown", "Default"));
        }

        @Test
        @DisplayName("should return true if role exists")
        void isRoleExists_true() {
            assertTrue(csvAuthentication.isRoleExists("Viewer", "Default"));
        }

        @Test
        @DisplayName("should return false if role does not exist")
        void isRoleExists_false() {
            assertFalse(csvAuthentication.isRoleExists("UnknownRole", "Default"));
        }

        @Test
        @DisplayName("isAuthorize should return false when no token is provided")
        void isAuthorize_noToken() {
            assertFalse(csvAuthentication.isAuthorize(Collections.emptyMap()));
        }


        @Test
        @DisplayName("isAuthorize should reject an incorrect token")
        void isAuthorize_invalidToken() {
            Map<String, Object> headers = Map.of("token", "invalid.token.string");
            assertFalse(csvAuthentication.isAuthorize(headers));
        }

        @Test
        void testDeptExists() {
            assertTrue(csvAuthentication.deptExists("Default", "trace1"));
            assertTrue(csvAuthentication.deptExists("Sales", "trace1"));
            assertFalse(csvAuthentication.deptExists("Marketing", "trace1"));
        }
    }

    @Nested
    @DisplayName("Data Modification")
    class DataModificationTests {

        @Test
        @DisplayName("should change password successfully")
        void changePassword_success() {
            Map<String, Object> data = Map.of("userName", "Demo", "oldPassword", "demopass", "newPassword", "newpass");
            int result = csvAuthentication.changePassword(data, "Default", "trace1");
            assertEquals(1, result);

            assertNull(csvAuthentication.authenticate(Map.of("userName", "Demo", "password", "demopass", "deptCode", "Default")));
            assertNotNull(csvAuthentication.authenticate(Map.of("userName", "Demo", "password", "newpass", "deptCode", "Default")));
        }

        @Test
        @DisplayName("should fail to change password with wrong old password")
        void changePassword_failWrongOldPassword() {
            Map<String, Object> data = Map.of("userName", "Demo", "oldPassword", "wrong", "newPassword", "newpass");
            int result = csvAuthentication.changePassword(data, "Default", "trace1");
            assertEquals(-2, result);
        }

        @Test
        @DisplayName("should delete user and their role mappings")
        void deleteUserById_success() {
            assertTrue(csvAuthentication.isUserExists("Demo", "Default"));
            assertEquals(1, csvAuthentication.selectRolesOfUser("Demo", "Default").size());

            int result = csvAuthentication.deleteUserById("Demo", "Default");
            assertEquals(1, result);

            assertFalse(csvAuthentication.isUserExists("Demo", "Default"));
            assertEquals(0, csvAuthentication.selectRolesOfUser("Demo", "Default").size());
        }

        @Test
        @DisplayName("should delete role and its user mappings")
        void deleteRoleById_success() {
            assertTrue(csvAuthentication.isRoleExists("Viewer", "Default"));
            assertEquals(1, csvAuthentication.selectUsersOfRole("Viewer", "Default").size());

            int result = csvAuthentication.deleteRoleById("Viewer", "Default");
            assertEquals(1, result);

            assertFalse(csvAuthentication.isRoleExists("Viewer", "Default"));
            // After deleting the role, the mapping is gone, so no users should be found for it.
            assertEquals(0, csvAuthentication.selectUsersOfRole("Viewer", "Default").size());
        }

        @Test
        @DisplayName("should delete department and all associated users and roles")
        void deleteDeptById_success() {
            assertTrue(csvAuthentication.deptExists("Sales", "trace1"));
            int result = csvAuthentication.deleteDeptById("Admin", Map.of("deptCode", "Sales"));
            assertEquals(1, result);
            assertFalse(csvAuthentication.deptExists("Sales", "trace1"));
            assertFalse(csvAuthentication.isUserExists("SalesUser", "Sales"));
            assertFalse(csvAuthentication.isRoleExists("SalesAdmin", "Sales"));
        }

        @Test
        @DisplayName("should create a new role")
        void createEditRole_create() {
            assertFalse(csvAuthentication.isRoleExists("Developer", "Default"));
            Map<String, Object> newRoleData = Map.of("name", "Developer", "department", "Default", "adminOption", "1");
            int result = csvAuthentication.CreateEditRole(newRoleData, "Default");
            assertEquals(1, result);
            assertTrue(csvAuthentication.isRoleExists("Developer", "Default"));
        }

        @Test
        @DisplayName("should edit an existing role")
        void createEditRole_edit() {
            assertEquals("1", csvAuthentication.getRoleByName("Viewer", "Default", null).get("reportOption"));
            Map<String, Object> updatedRoleData = Map.of("name", "Viewer", "department", "Default", "reportOption", "2");
            int result = csvAuthentication.CreateEditRole(updatedRoleData, "Default");
            assertEquals(1, result);
            assertEquals("2", csvAuthentication.getRoleByName("Viewer", "Default", null).get("reportOption"));
        }

        @Test
        @DisplayName("should update roles for a user")
        void updateRolesForUser_success() {
            assertEquals(1, csvAuthentication.selectRolesOfUser("Demo", "Default").size());
            Map<String, Object> data = Map.of("userName", "Demo", "roles", List.of("Administrator"));
            int result = csvAuthentication.updateRolesForUser(data, "Admin", "Default", "trace1");
            assertEquals(1, result);
            List<Map<String, Object>> roles = csvAuthentication.selectRolesOfUser("Demo", "Default");
            assertEquals(1, roles.size());
            assertEquals("Administrator", roles.get(0).get("name"));
        }

        @Test
        @DisplayName("should update users for a role")
        void updateUsersForRole_success() {
            assertEquals(1, csvAuthentication.selectUsersOfRole("Viewer", "Default").size());
            Map<String, Object> data = Map.of("roleName", "Viewer", "users", List.of("Admin", "Demo"));
            int result = csvAuthentication.updateUsersForRole(data, "Admin", "Default", "trace1");
            assertEquals(1, result);
            assertEquals(2, csvAuthentication.selectUsersOfRole("Viewer", "Default").size());
        }

        @Test
        @DisplayName("should rename a department for all users and roles")
        void createEditDepartment_renameSuccess() {
            assertTrue(csvAuthentication.deptExists("Sales", "trace1"));
            Map<String, Object> data = Map.of("oldDeptCode", "Sales", "newDeptCode", "Marketing");
            int result = csvAuthentication.CreateEditDepartment(data, "Sales");
            assertEquals(1, result);
            assertFalse(csvAuthentication.deptExists("Sales", "trace1"));
            assertTrue(csvAuthentication.deptExists("Marketing", "trace1"));
            assertNotNull(csvAuthentication.getUserByName("SalesUser", "Marketing", null));
            assertNotNull(csvAuthentication.getRoleByName("SalesAdmin", "Marketing", null));
        }
    }

    @Nested
    @DisplayName("Simple and Unimplemented Methods")
    class SimpleAndUnimplementedTests {

        @Test
        @DisplayName("setSource should update internal fields")
        void setSource_updatesFields() throws NoSuchFieldException, IllegalAccessException {
            DataSource mockDataSource = mock(DataSource.class);
            csvAuthentication.setSource(mockDataSource, "NewDept", "NewTrace");

            Field deptCodeField = CsvAuthenticationImpl.class.getDeclaredField("deptCode");
            deptCodeField.setAccessible(true);
            assertEquals("NewDept", deptCodeField.get(csvAuthentication));

            Field traceidField = CsvAuthenticationImpl.class.getDeclaredField("traceid");
            traceidField.setAccessible(true);
            assertEquals("NewTrace", traceidField.get(csvAuthentication));
        }

        @Test
        @DisplayName("generateEmbedToken should return dummy token with username")
        void generateEmbedToken_returnsDummy() {
            assertEquals("dummy-token", csvAuthentication.generateEmbedToken(Map.of("userName", "testuser"), null, null));
        }
    }

}
