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
    private final List<Payload> payloads;
    private final JacksonFactory jf;

    private String stripStackdriverEncapsulation(Event e, String input) {
        try {
            JsonParser jp = jf.createJsonParser(input);
            LogEntry entry = jp.parse(LogEntry.class);
            String ret = entry.getTextPayload();
            if (ret != null && !ret.isEmpty()) {
                return ret;
            }
            Map<String,Object> jret = entry.getJsonPayload();
            if (jret != null) {
                /* XXX This should be modified to avoid unnecessary serialization/deserialization
                 * and just return the required object */
                return entry.toString();
            }
        } catch (IOException exc) {
            // pass
        }
        return input;
    }

    private String stripEncapsulation(Event e, String input) {
        return stripStackdriverEncapsulation(e, input);
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
                // pass
            } catch (InstantiationException exc) {
                // pass
            } catch (IllegalAccessException exc) {
                // pass
            } catch (InvocationTargetException exc) {
                // pass
            }
            break;
        }

        return e;
    }

    public Parser() {
        jf = new JacksonFactory();
        payloads = new ArrayList<Payload>() {{
            add(new GLB());
            add(new OpenSSH());
            add(new Raw());
        }};
    }
}
