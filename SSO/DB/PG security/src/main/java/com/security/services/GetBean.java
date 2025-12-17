package com.security.services;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import jakarta.servlet.annotation.WebListener;

@Component
@WebListener
public class GetBean implements ApplicationContextAware {

    public static String REPOSITORYLOCATION_PATH;

    @Value("${app.repositoryLocation}")
    public void setRepositoryLocation(String repositoryLocation) {
            GetBean.REPOSITORYLOCATION_PATH = repositoryLocation;
    }

    public static ApplicationContext context;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        context = applicationContext;
    }
}
