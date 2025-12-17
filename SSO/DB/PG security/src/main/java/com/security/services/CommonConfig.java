package com.security.services;

import com.aivhub.logs.AuditLoggerUtil;
import com.aivhub.security.HeaderSecurity;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CommonConfig {

    public static Boolean isAuthneticated(String token,String deptCode,String traceid) {
        try {

                return new JwtTokenUtil().validateToken(token);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, CommonConfig.class, e.getMessage(),
                    traceid,deptCode, e);
            return false;
        }
    }

    public static String refreshToken(String token) {
        try {

            return new JwtTokenUtil().getUsernameFromToken(token,new HeaderSecurity().getSessionTime()).get("token").toString();
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, CommonConfig.class, e.getMessage(),
                    "Token Referesh","Token Referesh", e);
            return null;
        }
    }

    public Map<String, Object> getUserInfo(String userName) {

        Map<String, Object> obj = new HashMap<String, Object>();

       String utoken = new JwtTokenUtil().generateToken(userName,new HeaderSecurity().getSessionTime());

        obj.put("token",utoken);

        return obj;
    }

    //convert to Hex String
    public String fromHexString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return str.toString();
    }

    public String md5String(String input,String deptCode,String traceid) {
        try {

            // Static getInstance method is called with hashing MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // digest() method is called to calculate message digest
            //  of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, CommonConfig.class,e.getMessage(),
                    traceid,deptCode, e);
            return null;
        }
    }

}
