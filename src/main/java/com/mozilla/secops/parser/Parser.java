package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.io.IOException;

import java.lang.ReflectiveOperationException;

/**
 * Event parser
 *
 * {@link Parser} can be used to parse incoming events and generate {@link Event} objects.
 */
public class Parser {
    private static final long serialVersionUID = 1L;

    private final List<PayloadBase> payloads;
    private final JacksonFactory jf;
    private final Logger log;

    /**
     * Parse an ISO8601 date string and return a {@link DateTime} object.
     *
     * @param in Input string
     * @return Parsed {@link DateTime}, null if string could not be parsed
     */
    public static DateTime parseISO8601(String in) {
        DateTimeFormatter fmt = ISODateTimeFormat.dateTimeParser();
        return fmt.parseDateTime(in);
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

    /**
     * Parse an event
     *
     * @param input Input string
     * @return {@link Event}
     */
    public Event parse(String input) {
        if (input == null) {
            input = "";
        }

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

    /**
     * Create new parser instance
     */
    public Parser() {
        log = LoggerFactory.getLogger(Parser.class);
        jf = new JacksonFactory();
        payloads = new ArrayList<PayloadBase>();
        payloads.add(new GLB());
        payloads.add(new Cloudtrail());
        payloads.add(new OpenSSH());
        payloads.add(new Raw());
    }
}
