package com.example.KeycloakSecurity;

import jakarta.servlet.annotation.WebListener;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@WebListener
public class GetBean implements ApplicationContextAware {

    public static String REPOSITORYLOCATION_PATH;

    @Value("${app.repositoryLocation}")
    public void setRepositoryLocation(String repositoryLocation) {
            GetBean.REPOSITORYLOCATION_PATH = repositoryLocation;
    }

    public static Map<String, Object> adminLogin = new HashMap<>();


    public static String securityClass;


    @Value("${app.securityClass}")
    public void setSecurityClass(String securityClass) {
        GetBean.securityClass = securityClass;
    }


    public static String keycloakUrl;

    @Value("${keycloaks.url}")
    public void setkeycloakUrl(String keycloakUrl) {
        GetBean.keycloakUrl = keycloakUrl;
    }

    public static String gatewayApp;

    @Value("${app.gatewayApp}")
    public void setGatewayAppApp(String gatewayApp) {
        GetBean.gatewayApp = gatewayApp;
    }

    public static String frontendgatewayApp;

    @Value("${app.gatewayRedirectURL}")
    public void setFrontGatewayApp(String frontendgatewayApp) {
        GetBean.frontendgatewayApp = frontendgatewayApp;
    }


    public static String userURL;

    @Value("${keycloaks.users_url}")
    public void setUserURL(String userURL) {
        GetBean.userURL = userURL;
    }

    public static String rolesURL;

    @Value("${keycloaks.roles_url}")
    public void setRolesURL(String rolesURL) {
        GetBean.rolesURL = rolesURL;
    }



    public static ApplicationContext context;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        context = applicationContext;
    }
}
