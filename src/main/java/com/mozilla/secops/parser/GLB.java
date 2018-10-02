package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.logging.v2.model.HttpRequest;

import java.io.Serializable;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;

public class GLB extends Payload implements Serializable {
    private String requestMethod;
    private String userAgent;
    private String requestUrl;
    private String sourceAddress;

    @Override
    public Boolean matcher(String input) {
        try {
            JacksonFactory jf = new JacksonFactory();
            JsonParser jp = jf.createJsonParser(input);
            LogEntry entry = jp.parse(LogEntry.class);
            Map<String,Object> m = entry.getJsonPayload();
            String eType = (String)m.get("@type");
            if (eType.equals("type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry")) {
                return true;
            }
        } catch (IOException exc) { }
        return false;
    }

    public GLB() {
    }

    public GLB(String input, Event e) {
        setType(Payload.PayloadType.GLB);

        JacksonFactory jf = new JacksonFactory();
        LogEntry entry;
        try {
            JsonParser jp = jf.createJsonParser(input);
            entry = jp.parse(LogEntry.class);
        } catch (IOException exc) {
            return;
        }
        HttpRequest h = entry.getHttpRequest();

        sourceAddress = h.getRemoteIp();
        requestUrl = h.getRequestUrl();
        userAgent = h.getUserAgent();
        requestMethod = h.getRequestMethod();
    }

    public String getRequestUrl() {
        return requestUrl;
    }

    public String getUserAgent() {
        return userAgent;
    }
    
    public String getRequestMethod() {
        return requestMethod;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }
}
