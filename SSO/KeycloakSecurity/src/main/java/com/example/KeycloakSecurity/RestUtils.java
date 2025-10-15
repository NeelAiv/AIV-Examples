package com.example.KeycloakSecurity;

import com.aivhub.logs.AuditLoggerUtil;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


@Service
public class RestUtils {


    public String getRequest(String stUrl, Map<String, Object> data, String traceid) {
        String dc = data.containsKey("dc") ? data.get("dc").toString() : data.containsKey("deptCode") ?
                data.get("deptCode").toString() : "Default";
        try {


            AuditLoggerUtil.log(AuditLoggerUtil.RESTLOGGER, AuditLoggerUtil.INFO, RestUtils.class,
                    "Traceid :" + (!data.containsKey("traceid") ?
                            (!data.containsKey("userName") ? data.get("owner") : data.get("userName"))
                            : data.get("traceid")) + "Request made to " + stUrl +
                            " with headers : " + data.toString(), traceid, dc, null);

            HttpClient httpclient = HttpClients.createDefault();


            HttpGet httpget = null;
            httpget = new HttpGet(stUrl);

            Iterator<Map.Entry<String, Object>> entries = data.entrySet().iterator();
            while (entries.hasNext()) {
                Map.Entry<String, Object> entry = entries.next();
                if (entry.getKey().equals("deptCode")) {
                    httpget.addHeader("dc", entry.getValue().toString());
                }
                if (entry.getKey().equals("vdeptCode")) {
                    httpget.addHeader("vdc", entry.getValue().toString());
                }
                httpget.addHeader(entry.getKey(), entry.getValue().toString());
            }

            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            String resp = httpclient.execute(httpget, responseHandler);

            return resp;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, RestUtils.class, e.getMessage(), traceid, dc, e);
            return null;
        }
    }

    public String postRequest(String strUrl, Map<String, Object> header, List<Map<String, Object>> body, String traceid) {
        String dc = header.containsKey("dc") ? header.get("dc").toString() : header.containsKey("deptCode") ?
                header.get("deptCode").toString() : "Default";
        try {

            AuditLoggerUtil.log(AuditLoggerUtil.RESTLOGGER, AuditLoggerUtil.INFO, RestUtils.class,
                    "Traceid :" + (!header.containsKey("traceid") ?
                            (!header.containsKey("userName") ? header.get("owner") : header.get("userName"))
                            : header.get("traceid")) + "Request made to " + strUrl +
                            " with headers : " + header.toString() + " and body: " + body.toString(), traceid, dc, null);

            HttpClient httpclient = HttpClients.createDefault();

            String value = null;
            StringBuilder bdy = null;
            JSONObject bodyJson = null;
            StringEntity entity = null;
            StringBuilder head = new StringBuilder();
            bdy = new StringBuilder();


            HttpPost httppost = null;
            httppost = new HttpPost(strUrl);

           /* if (header.containsKey("id")) {
                httppost.addHeader("id", header.get("id").toString());
            }
            if (header.containsKey("timezone")) {
                httppost.addHeader("timezone", header.get("timezone").toString());
            }
            if (header.containsKey("owner")) {
                httppost.addHeader("owner", header.get("owner").toString());
            }
            if (header.containsKey("logs_category")) {
                httppost.addHeader("logs_category", header.get("logs_category").toString());
            }*/

            Iterator<Map.Entry<String, Object>> entries = header.entrySet().iterator();
            while (entries.hasNext()) {
                Map.Entry<String, Object> entry = entries.next();
                if (entry.getKey().equals("deptCode")) {
                    httppost.addHeader("dc", entry.getValue().toString());
                }
                if (entry.getKey().equals("vdeptCode")) {
                    httppost.addHeader("vdc", entry.getValue().toString());
                }
                httppost.addHeader(entry.getKey(), entry.getValue() == null ? null : entry.getValue().toString());
            }

            bodyJson = new JSONObject();
            for (Map<String, Object> m : body) {

                if (m.containsKey("bodyKey") && m.containsKey("bodyValue")) {
                    bodyJson.put(m.get("bodyKey").toString(), m.get("bodyValue").toString());
                } else {
                    for (Map.Entry<String, Object> g : m.entrySet()) {
                        bodyJson.put(g.getKey().toString(), g.getValue() == null ? JSONObject.NULL : g.getValue());
                    }

                }

            }

            entity = new StringEntity(bodyJson.toString());
            httppost.setEntity(entity);

            httppost.setHeader("Content-Type", "application/json");
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            String resp = httpclient.execute(httppost, responseHandler);

            return resp;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), traceid, dc, e);
            //AuditLoggerUtil.log(AuditLoggerUtil.SYSTEMLOGGER, AuditLoggerUtil.ERROR, BReportController.class, "Error while opening report design", e);
            return null;
        }
    }

    public String putRequest(String strUrl, Map<String, Object> header, List<Map<String, Object>> body, String traceid) {
        String dc = header.containsKey("dc") ? header.get("dc").toString() : header.containsKey("deptCode") ?
                header.get("deptCode").toString() : "Default";
        try {

            AuditLoggerUtil.log(AuditLoggerUtil.RESTLOGGER, AuditLoggerUtil.INFO, RestUtils.class,
                    "Traceid :" + (!header.containsKey("traceid") ?
                            (!header.containsKey("userName") ? header.get("owner") : header.get("userName"))
                            : header.get("traceid")) + "Request made to " + strUrl +
                            " with headers : " + header.toString() + " and body: " + body.toString(), traceid, dc, null);

            HttpClient httpclient = HttpClients.createDefault();

            String value = null;
            StringBuilder bdy = null;
            JSONObject bodyJson = null;
            StringEntity entity = null;
            StringBuilder head = new StringBuilder();
            bdy = new StringBuilder();


            HttpPut httppost = null;
            httppost = new HttpPut(strUrl);

           /* if (header.containsKey("id")) {
                httppost.addHeader("id", header.get("id").toString());
            }
            if (header.containsKey("timezone")) {
                httppost.addHeader("timezone", header.get("timezone").toString());
            }
            if (header.containsKey("owner")) {
                httppost.addHeader("owner", header.get("owner").toString());
            }
            if (header.containsKey("logs_category")) {
                httppost.addHeader("logs_category", header.get("logs_category").toString());
            }*/

            Iterator<Map.Entry<String, Object>> entries = header.entrySet().iterator();
            while (entries.hasNext()) {
                Map.Entry<String, Object> entry = entries.next();
                if (entry.getKey().equals("deptCode")) {
                    httppost.addHeader("dc", entry.getValue().toString());
                }
                if (entry.getKey().equals("vdeptCode")) {
                    httppost.addHeader("vdc", entry.getValue().toString());
                }
                httppost.addHeader(entry.getKey(), entry.getValue() == null ? null : entry.getValue().toString());
            }

            bodyJson = new JSONObject();
            for (Map<String, Object> m : body) {

                if (m.containsKey("bodyKey") && m.containsKey("bodyValue")) {
                    bodyJson.put(m.get("bodyKey").toString(), m.get("bodyValue").toString());
                } else {
                    for (Map.Entry<String, Object> g : m.entrySet()) {
                        bodyJson.put(g.getKey().toString(), g.getValue() == null ? JSONObject.NULL : g.getValue());
                    }

                }

            }

            entity = new StringEntity(bodyJson.toString());
            httppost.setEntity(entity);

            httppost.setHeader("Content-Type", "application/json");
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            String resp = httpclient.execute(httppost, responseHandler);

            return resp;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), traceid, dc, e);
            //AuditLoggerUtil.log(AuditLoggerUtil.SYSTEMLOGGER, AuditLoggerUtil.ERROR, BReportController.class, "Error while opening report design", e);
            return null;
        }
    }

    public String deleteRequest(String strUrl, Map<String, Object> header, String traceid) {
        String dc = header.containsKey("dc") ? header.get("dc").toString() : header.containsKey("deptCode") ?
                header.get("deptCode").toString() : "Default";
        try {
            AuditLoggerUtil.log(AuditLoggerUtil.RESTLOGGER, AuditLoggerUtil.INFO, RestUtils.class,
                    "Traceid :" + header.getOrDefault("traceid", header.getOrDefault("owner", ""))
                            + " DELETE Request made to " + strUrl + " with headers : " + header.toString(), traceid, dc, null);

            HttpClient httpclient = HttpClients.createDefault();
            HttpDelete httpDelete = new HttpDelete(strUrl);

            header.forEach((key, value) -> httpDelete.addHeader(key, value.toString()));

            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            return httpclient.execute(httpDelete, responseHandler);
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), traceid, dc, e);
            return null;
        }
    }

    public String encodedUrl(String url, Map<String, Object> data, String traceid) {
        String dc = data.containsKey("dc") ? data.get("dc").toString() : data.containsKey("deptCode") ?
                data.get("deptCode").toString() : "Default";
        try {
            HttpPost post = new HttpPost(url);
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();

            data.entrySet().forEach(h -> {
                nvps.add(new BasicNameValuePair(h.getKey(), h.getValue().toString()));
            });

            if (data.containsKey("Authorization")) {
                post.setHeader("Authorization", data.get("Authorization").toString());
            }

            post.setEntity(new UrlEncodedFormEntity(nvps, HTTP.UTF_8));

            // post.addHeader("Content-Type", "application/x-www-form-urlencoded");

            HttpClient httpclient = HttpClients.createDefault();
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            String response = httpclient.execute(post, responseHandler);
            return response;
        } catch (Exception e) {
            AuditLoggerUtil.log(AuditLoggerUtil.SECURITYLOGGER, AuditLoggerUtil.ERROR, this.getClass().getName(), e.getMessage(), traceid, dc, e);
            return null;
        }
    }

}
