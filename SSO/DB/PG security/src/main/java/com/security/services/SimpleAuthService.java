package com.security.services;

import com.aivhub.logs.AuditLoggerUtil;
import com.security.security.Be;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.util.*;

public class SimpleAuthService {

    NamedParameterJdbcTemplate namedjdbc;
    Map<String, Object> argobj = new HashMap<String, Object>();
    String sql =null;
    SimpleJdbcInsert insertUser,inserRole,insertDepartment,insertUserRoles;
    JdbcTemplate jdbc;

    String deptCode;
    String traceid;

    public SimpleAuthService(DataSource datasource,String deptCode,String traceid) {
        try {
            insertUser = new SimpleJdbcInsert(datasource).withSchemaName("security").withTableName("ai_user").usingGeneratedKeyColumns("id");
            inserRole = new SimpleJdbcInsert(datasource).withSchemaName("security").withTableName("ai_role").usingGeneratedKeyColumns("id");
            insertDepartment = new SimpleJdbcInsert(datasource).withSchemaName("security").withTableName("ai_department").usingGeneratedKeyColumns("id");
            insertUserRoles=new SimpleJdbcInsert(datasource).withSchemaName("security").withTableName("ai_user_role").usingGeneratedKeyColumns("id").
                    usingColumns("username","rolename");
            namedjdbc = new NamedParameterJdbcTemplate(datasource);
            jdbc = new JdbcTemplate(datasource);
            this.deptCode =deptCode;
            this.traceid = traceid;

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,SimpleAuthImpl.class,e.getMessage(),
                    this.traceid,this.deptCode, e);
        }
    }

    public String validatePassword(String userNameIN, String passwordIN,String deptName,String salt) {

        try {

             sql = "select password,id from ai_user where userName=:userName and department=:deptcode and status='Active'";
            Map<String, Object> resultSet = namedjdbc.queryForMap(sql,new MapSqlParameterSource("userName", userNameIN).addValue("deptcode", deptName));

            String encPass= new CommonConfig().md5String(salt+new Be().decrypt(resultSet.get("password").toString(),Be.EncKey),this.traceid,this.deptCode);

            if (resultSet!=null && encPass.equals(passwordIN)) {
                return resultSet.get("id").toString();       //return userId if uerName and password are correct
            } else {
                return "0";           //returns 0 if incorrect password
            }

        } catch (Exception e) {
            return "0";               //returns 0 if no record found with specified userName
        }
    }

    public String getRoleNamesForUser(String userName,String deptCode) {
        sql="select string_agg(roleName, ',') AS roles from ai_user_role where userName=:userName GROUP BY userName";
        try{
            String roles=namedjdbc.queryForObject(sql, new MapSqlParameterSource("userName", userName), String.class);

            return roles;
        }
        catch(Exception e){
            return "";
        }
    }

    public Map<String, Object> getUserRoleFeatures(String userName,String deptCode) {
        argobj.clear();
        argobj.put("userName", userName);
        String roles = getRoleNamesForUser(userName,deptCode);
        if(roles!=null && !roles.isEmpty())argobj.put("roles", Arrays.asList(roles.split(",")));
        else argobj.put("roles",null);

        argobj.put("currentDate", Calendar.getInstance().getTime());
        argobj.put("deptcode", deptCode);

        try{
                sql="select u.id as \"id\" ,u.firstName as \"firstName\",u.lastName as \"lastName\",u.userName as \"userName\",u.status as \"status\",u.userType as \"userType\",u.email as \"email\",u.homeFolder as \"homeFolder\",(select userName from ai_user where cast(id as character varying   ) = u.backupUserId) as \"backupUserId\",u.managerUserId as \"managerUserId\", "
                    +"u.default_dashboard as \"default_dashboard\",u.landing_page as \"landing_page\",u.locale as \"locale\",u.timezone as \"timezone\",u.theme as \"theme\",u.notification as \"notification\",u.department as \"department\",u.showname as \"showname\",u.showimage as \"showimage\", "
                    +"Max(f.dashboardOption) as \"dashboardOption\",Max(f.alertsOption) as \"alertsOption\", "
                    +"Max(f.reportOption) as \"reportOption\",Max(f.mergeReportOption) as \"mergeReportOption\",Max(f.adhocOption) as \"adhocOption\",Max(f.resourceOption) as \"resourceOption\",Max(f.quickRunOption) as \"quickRunOption\",Max(f.mappingOption) as \"mappingOption\", "
                    +"Max(f.messageOption) as \"messageOption\",Max(f.datasetOption) as \"datasetOption\",Max(f.parameterOption) as \"parameterOption\",Max(f.annotationOption) as \"annotationOption\", "
                    +"Max(f.notificationOption) as \"notificationOption\",Max(f.requestOption) as \"requestOption\",Max(f.adminOption) as \"adminOption\",Max(f.scheduleOption) as \"scheduleOption\",MAX(f.webhookOption) as \"webhookOption\",null as \"backupFor\" from "
                    +"(select dashboardOption,alertsOption,reportOption,mergeReportOption,adhocOption,resourceOption,quickRunOption,mappingOption,messageOption,datasetOption, "
                    +"parameterOption,annotationOption,notificationOption,requestOption,adminOption,scheduleOption,webhookOption from ai_user where userName=:userName and department=:deptcode union all "
                    +"select dashboardOption,alertsOption,reportOption,mergeReportOption,adhocOption,resourceOption,quickRunOption,mappingOption,messageOption,datasetOption, "
                    +"parameterOption,annotationOption,notificationOption,requestOption,adminOption,scheduleOption,webhookOption "
                    +"from ai_role where name in (:roles) and department=:deptcode )as f,ai_user u  "
                    +"where u.userName=:userName and u.department=:deptcode and u.status='Active' group by u.id";

            return (Map<String, Object>) namedjdbc.queryForMap(sql, argobj);

        }
        catch(Exception e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR,SimpleAuthImpl.class,e.getMessage(),this.traceid,this.deptCode, e);
            return null;
        }
    }

    public List<Map<String, Object>> getAllUsers(String userName, String deptCode) {
        argobj.clear();
        argobj.put("deptcode", deptCode);

        try{
            sql ="select u.id as \"id\" ,u.firstName as \"firstName\",u.lastName as \"lastName\",u.userName as \"userName\",u.status as \"status\",u.userType as \"userType\",u.email as \"email\",u.homeFolder as \"homeFolder\",u.backupUserId as \"backupUserId\",u.managerUserId as \"managerUserId\", "
                    +"u.default_dashboard as \"default_dashboard\",u.landing_page as \"landing_page\",u.locale as \"locale\",u.timezone as \"timezone\",u.theme as \"theme\",u.notification as \"notification\",u.department as \"department\",u.showname as \"showname\",u.showimage as \"showimage\", "
                    +"u.dashboardOption as \"dashboardOption\",u.alertsOption as \"alertsOption\", "
                    +"u.reportOption as \"reportOption\",u.mergeReportOption as \"mergeReportOption\",u.adhocOption as \"adhocOption\",u.resourceOption as \"resourceOption\",u.quickRunOption as \"quickRunOption\",u.mappingOption as \"mappingOption\", "
                    +"u.messageOption as \"messageOption\",u.datasetOption as \"datasetOption\",u.parameterOption as \"parameterOption\",u.annotationOption as \"annotationOption\", "
                    +"u.notificationOption as \"notificationOption\",u.requestOption as \"requestOption\",u.adminOption as \"adminOption\",u.scheduleOption as \"scheduleOption\",u.webhookOption as \"webhookOption\" from ai_user u where u.department=:deptcode";
            return namedjdbc.queryForList(sql, argobj);

        }
        catch(EmptyResultDataAccessException e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"Error Getting all  users",this.traceid,this.deptCode, e);
            return null;
        }
    }

    public List<Map<String, Object>> getAllRoles(String deptCode) {

        sql="select "+
                "u.id as \"id\", u.name as \"name\",u.email as \"email\",u.description as \"description\",u.dashboardOption as \"dashboardOption\",u.alertsOption as \"alertsOption\", "
                +"u.reportOption as \"reportOption\",u.mergeReportOption as \"mergeReportOption\",u.adhocOption as \"adhocOption\",u.resourceOption as \"resourceOption\",u.quickRunOption as \"quickRunOption\",u.mappingOption as \"mappingOption\", "
                +"u.messageOption as \"messageOption\",u.datasetOption as \"datasetOption\",u.parameterOption as \"parameterOption\",u.annotationOption as \"annotationOption\", "
                +"u.notificationOption as \"notificationOption\",u.requestOption as \"requestOption\",u.adminOption as \"adminOption\",u.scheduleOption as \"scheduleOption\",u.webhookOption as \"webhookOption\",u.department as \"department\" "+
                " from ai_role as u where department=:deptcode";
        return namedjdbc.queryForList(sql,new MapSqlParameterSource("deptcode", deptCode));
    }

    public List<Map<String, Object>> getAllDepartments(String deptCode) {

        sql="select "+
                "u.id as \"id\",u.deptname as \"deptname\",u.deptcode as \"deptcode\" from ai_department as u";
        return namedjdbc.queryForList(sql,new MapSqlParameterSource());
    }

    public List<Map<String, Object>> getUserbyRole(String rolename, String deptCode){
        argobj.clear();
        argobj.put("roleName", rolename);
        argobj.put("deptcode", deptCode);

        try{
            sql="select u.id as \"id\" ,u.firstName as \"firstName\",u.lastName as \"lastName\",u.userName as \"userName\",u.status as \"status\",u.userType as \"userType\",u.email as \"email\",u.homeFolder as \"homeFolder\",u.backupUserId as \"backupUserId\",u.managerUserId as \"managerUserId\", "
                    +"u.default_dashboard as \"default_dashboard\",u.landing_page as \"landing_page\",u.locale as \"locale\",u.timezone as \"timezone\",u.theme as \"theme\",u.notification as \"notification\",u.department as \"department\",u.showname as \"showname\",u.showimage as \"showimage\", "
                    +"u.dashboardOption as \"dashboardOption\",u.alertsOption as \"alertsOption\", "
                    +"u.reportOption as \"reportOption\",u.mergeReportOption as \"mergeReportOption\",u.adhocOption as \"adhocOption\",u.resourceOption as \"resourceOption\",u.quickRunOption as \"quickRunOption\",u.mappingOption as \"mappingOption\", "
                    +"u.messageOption as \"messageOption\",u.datasetOption as \"datasetOption\",u.parameterOption as \"parameterOption\",u.annotationOption as \"annotationOption\", "
                    +"u.notificationOption as \"notificationOption\",u.requestOption as \"requestOption\",u.adminOption as \"adminOption\",u.scheduleOption as \"scheduleOption\",u.webhookOption as \"webhookOption\" from ai_user u where userName in (select userName from ai_user_role where roleName=:roleName) and department=:deptcode and status='Active'";
            return namedjdbc.queryForList(sql,argobj);
        }
        catch(Exception e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,e.getMessage(),this.traceid,this.deptCode, e);
            return null;
        }
    }

    public List<Map<String, Object>> getRolesForUser(String userName,String deptCode) {
        sql="select * from ai_role where name in (select roleName from ai_user_role where userName=:userName) and department=:deptcode";
        try{
            return namedjdbc.queryForList(sql, new MapSqlParameterSource("userName", userName).addValue("deptcode",deptCode));
        }
        catch(Exception e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,e.getMessage(),this.traceid,this.deptCode, e);
            return null;
        }
    }


    public Map<String, Object> getUserByName(String userNameIN,String deptCode) {

        argobj.clear();
        argobj.put("userName", userNameIN);
        argobj.put("deptcode", deptCode);

        try{

            sql ="select u.id as \"id\" ,u.firstName as \"firstName\",u.lastName as \"lastName\",u.userName as \"userName\",u.status as \"status\",u.userType as \"userType\",u.email as \"email\",u.homeFolder as \"homeFolder\",u.backupUserId as \"backupUserId\",u.managerUserId as \"managerUserId\", "
                    +"u.default_dashboard as \"default_dashboard\",u.landing_page as \"landing_page\",u.locale as \"locale\",u.timezone as \"timezone\",u.theme as \"theme\",u.notification as \"notification\",u.department as \"department\",u.showname as \"showname\",u.showimage as \"showimage\", "
                    +"u.dashboardOption as \"dashboardOption\",u.alertsOption as \"alertsOption\", "
                    +"u.reportOption as \"reportOption\",u.mergeReportOption as \"mergeReportOption\",u.adhocOption as \"adhocOption\",u.resourceOption as \"resourceOption\",u.quickRunOption as \"quickRunOption\",u.mappingOption as \"mappingOption\", "
                    +"u.messageOption as \"messageOption\",u.datasetOption as \"datasetOption\",u.parameterOption as \"parameterOption\",u.annotationOption as \"annotationOption\", "
                    +"u.notificationOption as \"notificationOption\",u.requestOption as \"requestOption\",u.adminOption as \"adminOption\",u.scheduleOption as \"scheduleOption\",u.webhookOption as \"webhookOption\" from ai_user u where u.userName=:userName and u.department=:deptcode";
            return (Map<String, Object>) namedjdbc.queryForMap(sql, argobj);

        }
        catch(Exception e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"User doesnt exist with name:"+userNameIN,this.traceid,this.deptCode, e);
            return null;
        }
    }

    public Map<String, Object> getRoleByName(String roleNameIN,String deptCode) {
        argobj.clear();
        argobj.put("name", roleNameIN);
        argobj.put("deptcode", deptCode);
        try{
            sql ="select * from ai_role where name=:name and department=:deptcode";
            return (Map<String, Object>) namedjdbc.queryForMap(sql, argobj);
        }
        catch (Exception e) {

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"role doesnt exist:"+roleNameIN,this.traceid,this.deptCode, e);
            return null;
        }
    }

    public int CreateUser(Map<String, Object> data, String deptCode) {
        try {
            argobj.clear();
            argobj.putAll(data);

          //  insertUser.withSchemaName("\"" + deptCode + "\"");
            insertUser.withTableName("ai_user");
            insertUser.usingColumns("firstName","lastName","userName","status","password","email","homeFolder",
                    "backupUserId","managerUserId","dashboardOption","alertsOption","reportOption","mergeReportOption",
                    "adhocOption","resourceOption","quickRunOption","mappingOption","messageOption","datasetOption","parameterOption",
                    "annotationOption","notificationOption","requestOption","adminOption","scheduleOption","webhookOption","userType"
                    ,"default_dashboard","landing_page","locale","timezone","theme","notification","showname","showimage",
                    "department");

            return insertUser.executeAndReturnKey(argobj).intValue();
        } catch (Exception e) {

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"Cannot create/edit user.",this.traceid,this.deptCode, e);
            return -1;
        }
    }

    public int updateUserProfile(Map<String, Object> userIN) {
        try {
            String sql = "update ai_user set showname=:showname,showimage=:showimage where userName=:userName";
            return namedjdbc.update(sql, userIN);    // returns the number of rows affected
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "updateUser() userName:" + userIN.get("userName"),this.traceid,this.deptCode, e);
            return 0;                          //if no user exists with given userId
        }
    }

    public int updateUserPersonalizeInfo(Map<String, Object> details) {

        sql = "update ai_user set default_dashboard=:default_dashboard,landing_page=:landing_page,locale=:locale,timezone=:timezone,notification=:notification where username=:username";

        return namedjdbc.update(sql, details);
    }

    public int updateUser(Map<String, Object> userIN,String deptCode) {
        argobj.clear();
        argobj.putAll(userIN);
        argobj.put("deptcode", deptCode);
        try{

            sql= "update ai_user set firstName=:firstName,lastName=:lastName,status=:status,"
                    +"email=:email, "
                    +"dashboardOption=:dashboardOption,alertsOption=:alertsOption,reportOption=:reportOption,mergeReportOption=:mergeReportOption,"
                    +"adhocOption=:adhocOption,resourceOption=:resourceOption,quickRunOption=:quickRunOption,mappingOption=:mappingOption,messageOption=:messageOption,datasetOption=:datasetOption,"
                    +"parameterOption=:parameterOption,annotationOption=:annotationOption,notificationOption=:notificationOption,requestOption=:requestOption,"
                    +"adminOption=:adminOption,scheduleOption=:scheduleOption,webhookOption=:webhookOption,userType=:userType,landing_page=:landing_page,password=(case when 'true'=:pwdChngFlag then :password else password end) where userName=:userName and department=:deptcode";


            return namedjdbc.update(sql, argobj);    // returns the number of rows affected
        }
        catch(Exception e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"updateUser() userName:"+userIN.get("userName"),this.traceid,this.deptCode, e);
            return 0;                          //if no user exists with given userId
        }
    }

    public boolean isRoleExists(String name,String deptCode) {
        argobj.clear();
        argobj.put("name", name);
        sql = "select * from ai_role where name=:name";
        List<Map<String, Object>> users = namedjdbc.queryForList(sql, argobj);
        if (users.size() == 0)
            return false;
        else
            return true;
    }

    public boolean isUserExist(String userName) {
        argobj.clear();
        argobj.put("username", userName);
        sql = "select * from ai_user where userName=:username";
        List<Map<String, Object>> users = namedjdbc.queryForList(sql, argobj);
        if (users.size() == 0)
            return false;
        else
            return true;
    }

    public int CreateRole(Map<String, Object> data, String deptCode) {
        try {
            argobj.clear();
            argobj.putAll(data);

          //  inserRole.withSchemaName("\"" + deptCode + "\"");
            inserRole.withTableName("ai_role");
            inserRole.usingColumns("name","email","description","dashboardOption","alertsOption","reportOption","mergeReportOption",
                    "adhocOption","resourceOption","quickRunOption","mappingOption","messageOption","datasetOption","parameterOption",
                    "annotationOption","webhookOption","notificationOption","requestOption","adminOption","scheduleOption",
                    "department");

            return inserRole.executeAndReturnKey(argobj).intValue();
        } catch (Exception e) {

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"Cannot create/edit user.",this.traceid,this.deptCode, e);
            return -1;
        }
    }

    public int updateRole(Map<String, Object> roleIN,String deptCode) {
        argobj.clear();
        argobj.putAll(roleIN);
        argobj.put("deptcode", deptCode);
        argobj.put("description", roleIN.containsKey("description") ? roleIN.get("description").toString() : null);
        try{

            sql= "update ai_role set description=:description,"
                    +"email=:email, "
                    +"dashboardOption=:dashboardOption,alertsOption=:alertsOption,reportOption=:reportOption,mergeReportOption=:mergeReportOption,"
                    +"adhocOption=:adhocOption,resourceOption=:resourceOption,quickRunOption=:quickRunOption,mappingOption=:mappingOption,messageOption=:messageOption,datasetOption=:datasetOption,"
                    +"parameterOption=:parameterOption,annotationOption=:annotationOption,notificationOption=:notificationOption,requestOption=:requestOption,"
                    +"adminOption=:adminOption,scheduleOption=:scheduleOption,webhookOption=:webhookOption where name=:name and department=:deptcode";


            return namedjdbc.update(sql, argobj);    // returns the number of rows affected
        }
        catch(Exception e){
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"updateUser() userName:"+roleIN.get("name"),this.traceid,this.deptCode, e);
            return 0;                          //if no user exists with given userId
        }
    }

    public int UpdateDepartment(Map<String, Object> data, String deptCode) {
        try {
            argobj.clear();
            argobj.putAll(data);

            sql= "update ai_department set deptname=:deptname "
                    +"where id=:id";

            return namedjdbc.update(sql, argobj);
        } catch (Exception e) {

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"Cannot create/edit user.",this.traceid,this.deptCode, e);
            return -1;
        }
    }

    public int CreateDepartment(Map<String, Object> data, String deptCode) {
        try {
            argobj.clear();
            argobj.putAll(data);

          //  inserRole.withSchemaName("\"" + deptCode + "\"");
            insertDepartment.withTableName("ai_department");
            insertDepartment.usingColumns("deptname","deptcode");

            return insertDepartment.executeAndReturnKey(argobj).intValue();
        } catch (Exception e) {

            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER,AuditLoggerUtil.ERROR, SimpleAuthService.class,"Cannot create/edit user.",this.traceid,this.deptCode, e);
            return -1;
        }
    }

    public List<Map<String, Object>> getAllDeptWithAdmins() {
        try {
            String sql = "select d.id AS id, d.deptName AS \"deptName\" ,d.deptCode AS \"deptCode\",u.userName AS \"userName\" from ai_department d left join ai_user u on d.deptCode=u.department and u.adminOption='2'";
            return jdbc.queryForList(sql);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, e.getMessage(),this.traceid,this.deptCode, e);
            return null;
        }
    }


    public int deleteDeptById(String owner, Map<String, Object> deptId) {
        try {
            sql = "Delete from ai_department where id in (:deptId)";
            return namedjdbc.update(sql, deptId);   //returns the number of rows affected
        } catch (EmptyResultDataAccessException e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, e.getMessage(),this.traceid,this.deptCode, e);
            return 0;
        }
    }

    public int deleteUser(String userNameIN,String deptcode) {

        try {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, SimpleAuthService.class, "deleteUser() userName:" + userNameIN,this.traceid,this.deptCode, null);
            sql = "Delete from ai_user where userName=:userName and department=:deptcode";
            return namedjdbc.update(sql, new MapSqlParameterSource("userName", userNameIN).addValue("deptcode", deptcode)); // returns the number of rows affected
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "deleteUser() userName:" + userNameIN,this.traceid,this.deptCode, e);
            return 0;             //if no user exists with given userName
        }
    }

    public int deleteRole(String roleNameIN,String deptCode) {
        try {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.INFO, SimpleAuthService.class, "deleteRole() roleNameIN:" + roleNameIN,this.traceid,this.deptCode, null);
            sql = "Delete from ai_role where name=:name and department=:deptcode";
            return namedjdbc.update(sql, new MapSqlParameterSource("name", roleNameIN).addValue("deptcode", deptCode));   //returns the number of rows affected
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "deleteRole() roleNameIN:" + roleNameIN,this.traceid,this.deptCode, e);
            return 0;               //returns 0 if no record found with specified id
        }
    }

    public void addRolesForUser(Map<String, Object> data) {

        String[] roles={};
        roles=data.get("roles").toString().length() > 0 ? data.get("roles").toString().split(",") : new String[0];
        if(roles.length>0){
            SqlParameterSource[] namedParametersArray   = new MapSqlParameterSource[roles.length];
            for (int i=0;i<roles.length;i++) {

                namedParametersArray[i] = new MapSqlParameterSource("username",data.get("userName")).addValue("rolename", roles[i]);
            }
            insertUserRoles.executeBatch(namedParametersArray);
        }
    }

    public int deleteRolesForUser(String userName) {
        try {
            sql = "Delete from ai_user_role where userName=:userName";
            return namedjdbc.update(sql, new MapSqlParameterSource("userName", userName));   //returns the number of rows affected
        } catch (Exception e) {
            return 0;               //returns 0 if no record found
        }
    }

    public int changePassword(Map<String, Object> user,String deptCode,String traceid) {
        try {
            argobj.clear();
            argobj.putAll(user);

            sql = "select password from ai_user where userName=:userName";

            String salt = user.get("salt").toString();
            Map<String, Object> u = (Map<String, Object>) namedjdbc.queryForMap(sql, argobj);

            try {
                user.put("password",new Be().encrypt(user.get("password").toString(), Be.EncKey));
            } catch (GeneralSecurityException e) {
                AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "Password Encryption failed: " + user.get("userName").toString(), traceid, deptCode, e);
                return -1;
            }

            String encPass= (new Be()).encrypt(user.get("oldPassword").toString(), "0fc79bc2a4f6411ca1a9cb325ee8a3a2");

            if (u!=null && encPass.equals(u.get("password").toString())) {
                argobj.clear();
                argobj.putAll(user);
                sql= "update ai_user set password=:password "
                        +"where userName=:userName";

                return namedjdbc.update(sql, argobj);     //return userId if uerName and password are correct
            } else {
                return 0;           //returns 0 if incorrect password
            }


        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "User doesnt exist with name:" + user.get("userName").toString(), traceid, deptCode, e);
            return -1;
        }
    }

    public Map<String, Object> getUserDetails(String userNameIN) {

        argobj.clear();
        argobj.put("userName", userNameIN);

        try {

            sql = "select u.id as \"id\" ,u.firstName as \"firstName\",u.lastName as \"lastName\",u.userName as \"userName\",u.status as \"status\",u.userType as \"userType\",u.email as \"email\",u.homeFolder as \"homeFolder\",u.backupUserId as \"backupUserId\",u.managerUserId as \"managerUserId\", "
                    + "u.default_dashboard as \"default_dashboard\",u.landing_page as \"landing_page\",u.locale as \"locale\",u.timezone as \"timezone\",u.theme as \"theme\",u.notification as \"notification\",u.department as \"department\",u.showname as \"showname\",u.showimage as \"showimage\", "
                    + "u.dashboardOption as \"dashboardOption\",u.alertsOption as \"alertsOption\", "
                    + "u.reportOption as \"reportOption\",u.mergeReportOption as \"mergeReportOption\",u.adhocOption as \"adhocOption\",u.resourceOption as \"resourceOption\",u.quickRunOption as \"quickRunOption\",u.mappingOption as \"mappingOption\", "
                    + "u.messageOption as \"messageOption\",u.datasetOption as \"datasetOption\",u.parameterOption as \"parameterOption\",u.annotationOption as \"annotationOption\", "
                    + "u.notificationOption as \"notificationOption\",u.requestOption as \"requestOption\",u.adminOption as \"adminOption\",u.scheduleOption as \"scheduleOption\",u.webhookOption as \"webhookOption\", u.department as \"department\" from ai_user u where u.userName=:userName";
            return (Map<String, Object>) namedjdbc.queryForMap(sql, argobj);

        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.DBLOGGER, AuditLoggerUtil.ERROR, SimpleAuthService.class, "User doesnt exist with name:" + userNameIN, this.traceid, this.deptCode, e);
            return null;
        }
    }

    public int deleteUsersForRole(String roleName) {
        try{
            sql="Delete from ai_user_role where roleName=:roleName";
            return namedjdbc.update(sql, new MapSqlParameterSource("roleName",roleName));   //returns the number of rows affected
        }
        catch (Exception e) {
            return 0;               //returns 0 if no record found
        }
    }



    public int updateUsersForRole(Map<String,Object> userRoleData,String updatedBy,String deptCode){
        deleteUsersForRole(userRoleData.get("roleName").toString());
        addUsersForRole(userRoleData);
        return 1;
    }


    public void addUsersForRole(Map<String, Object> data) {

        String[] users={};
        users= data.get("users").toString().length() >  0 ? data.get("users").toString().split(",") : new String[0];
        if(users.length>0){
            SqlParameterSource[] namedParametersArray   = new MapSqlParameterSource[users.length];

            for (int i=0;i<users.length;i++) {

                namedParametersArray[i] = new MapSqlParameterSource("userName",users[i]).addValue("roleName",data.get("roleName"));
            }
            insertUserRoles.executeBatch(namedParametersArray);
        }
    }

}
