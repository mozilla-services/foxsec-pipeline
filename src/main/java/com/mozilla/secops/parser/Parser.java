package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.io.IOException;

import java.lang.reflect.InvocationTargetException;

public class Parser {
    private List<Payload> payloads;

    private String stripStackdriverEncapsulation(Event e, String input) throws IOException {
        JacksonFactory jf = new JacksonFactory();
        JsonParser jp = jf.createJsonParser(input);
        LogEntry entry = jp.parse(LogEntry.class);
        String ret = entry.getTextPayload();
        if (ret != null && !ret.isEmpty()) {
            return ret;
        }
        Map<String,Object> jret = entry.getJsonPayload();
        if (jret != null) {
            return entry.toString();
        }
        return input;
    }

    private String stripEncapsulation(Event e, String input) {
        try {
            input = stripStackdriverEncapsulation(e, input);
        } catch (java.io.IOException exc) { }
        return input;
    }

    @SuppressWarnings("unchecked")
    public Event parse(String input) {
        Event e = new Event();
        input = stripEncapsulation(e, input);

        for (Payload p : payloads) {
            if (!p.matcher(input)) {
                continue;
            }
            Class cls = p.getClass();
            try {
                e.setPayload((Payload)cls.getConstructor(String.class, Event.class).newInstance(input, e));
            } catch (NoSuchMethodException exc) {
            } catch (InstantiationException exc) {
            } catch (IllegalAccessException exc) {
            } catch (InvocationTargetException exc) { }
            break;
        }

        return e;
    }

    public Parser() {
        payloads = new ArrayList<Payload>() {{
            add(new GLB());
            add(new OpenSSH());
            add(new Raw());
        }};
    }
}
