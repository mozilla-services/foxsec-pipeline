package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.logging.v2.model.HttpRequest;

import org.joda.time.DateTime;

import java.io.Serializable;
import java.io.IOException;
import java.util.Map;

public class GLB extends PayloadBase implements Serializable {
    private static final long serialVersionUID = 1L;

    private final JacksonFactory jfmatcher;

    private String requestMethod;
    private String userAgent;
    private String requestUrl;
    private String sourceAddress;

    @Override
    public Boolean matcher(String input) {
        try {
            JsonParser jp = jfmatcher.createJsonParser(input);
            LogEntry entry = jp.parse(LogEntry.class);
            Map<String,Object> m = entry.getJsonPayload();
            String eType = (String)m.get("@type");
            if (eType.equals("type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry")) {
                return true;
            }
        } catch (IOException exc) {
            // pass
        } catch (IllegalArgumentException exc) {
            // pass
        }
        return false;
    }

    @Override
    public Payload.PayloadType getType() {
        return Payload.PayloadType.GLB;
    }

    public GLB() {
        jfmatcher = new JacksonFactory();
    }

    public GLB(String input, Event e) {
        jfmatcher = null;
        // Use method local JacksonFactory as the object is not serializable, and this event
        // may be passed around
        JacksonFactory jf = new JacksonFactory();
        LogEntry entry;
        try {
            JsonParser jp = jf.createJsonParser(input);
            entry = jp.parse(LogEntry.class);
        } catch (IOException exc) {
            return;
        }
        HttpRequest h = entry.getHttpRequest();
        if (h == null) {
            return;
        }

        String ets = entry.getTimestamp();
        if (ets != null) {
            DateTime d = Parser.parseISO8601(ets);
            if (d != null) {
                e.setTimestamp(d);
            }
        }

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
