package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;

import org.joda.time.DateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.io.IOException;

import java.lang.ReflectiveOperationException;

public class Parser {
    private static final long serialVersionUID = 1L;

    private final List<PayloadBase> payloads;
    private final JacksonFactory jf;
    private final Logger log;

    public static DateTime parseISO8601(String in) {
        java.time.format.DateTimeFormatter fmt = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ss.nnnnnnnnnX");
        ZonedDateTime z;
        try {
            z = ZonedDateTime.parse(in, fmt);
        } catch (DateTimeParseException exc) {
            return null;
        }
        return new DateTime(z.toInstant().toEpochMilli());
    }

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
                // XXX Serialize the Stackdriver JSON data and emit a string for use in the
                // matchers. This is inefficient and we could probably look at changing this
                // to return a different type to avoid having to deserialize the data twice.
                return entry.toString();
            }
        } catch (IOException exc) {
            // pass
        } catch (IllegalArgumentException exc) {
            // pass
        }
        // If the input data could not be converted into a Stackdriver LogEntry just return
        // it as is.
        return input;
    }

    private String stripEncapsulation(Event e, String input) {
        return stripStackdriverEncapsulation(e, input);
    }

    public Event parse(String input) {
        Event e = new Event();
        input = stripEncapsulation(e, input);

        for (PayloadBase p : payloads) {
            if (!p.matcher(input)) {
                continue;
            }
            Class<?> cls = p.getClass();
            try {
                e.setPayload((PayloadBase)cls.getConstructor(String.class, Event.class).newInstance(input, e));
            } catch (ReflectiveOperationException exc) {
                log.warn(exc.getMessage());
            }
            break;
        }

        return e;
    }

    public Parser() {
        log = LoggerFactory.getLogger(Parser.class);
        jf = new JacksonFactory();
        payloads = new ArrayList<PayloadBase>();
        payloads.add(new GLB());
        payloads.add(new OpenSSH());
        payloads.add(new Raw());
    }
}
