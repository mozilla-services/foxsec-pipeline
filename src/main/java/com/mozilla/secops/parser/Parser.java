package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.logging.v2.model.MonitoredResource;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.identity.IdentityManager;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Event parser
 *
 * <p>{@link Parser} can be used to parse incoming events and generate {@link Event} objects.
 */
public class Parser {
  private static final long serialVersionUID = 1L;

  private final List<PayloadBase> payloads;
  private final JacksonFactory jf;
  private final Logger log;
  private GeoIP geoip;

  public static final String SYSLOG_TS_RE = "\\S{3} {1,2}\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}";

  private IdentityManager idmanager;

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

  /**
   * Process the value of an X-Forwarded-For header, returning an array of each address in the
   * header or null if invalid
   *
   * @param in Input string
   * @return Array of addresses, beginning from the left-most, or null on failure
   */
  public static String[] parseXForwardedFor(String in) {
    if (in == null) {
      return null;
    } else if (in.isEmpty()) {
      return new String[0];
    }
    String[] v = in.split(", ?");
    InetAddressValidator iav = new InetAddressValidator();
    for (String t : v) {
      if (!(iav.isValid(t))) {
        return null;
      }
    }
    return v;
  }

  private String getStackdriverProject(LogEntry entry) {
    if (entry == null) {
      return null;
    }
    MonitoredResource mr = entry.getResource();
    if (mr == null) {
      return null;
    }
    Map<String, String> labels = mr.getLabels();
    if (labels == null) {
      return null;
    }
    return labels.get("project_id");
  }

  private String stripStackdriverEncapsulation(Event e, String input, ParserState state) {
    try {
      JsonParser jp = jf.createJsonParser(input);
      LogEntry entry = jp.parse(LogEntry.class);

      e.setStackdriverProject(getStackdriverProject(entry));
      e.setStackdriverLabels(entry.getLabels());

      // We were able to deserialize the LogEntry so store it as a hint in the state
      state.setLogEntryHint(entry);

      String ret = entry.getTextPayload();
      if (ret != null && !ret.isEmpty()) {
        return ret;
      }
      Map<String, Object> jret = entry.getJsonPayload();
      if (jret == null) {
        jret = entry.getProtoPayload();
      }
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

  private String stripMozlog(Event e, String input, ParserState state) {
    LogEntry entry = state.getLogEntryHint();
    if (entry != null) {
      // If we have an existing LogEntry hint, attempt to treat a present jsonPayload
      // as Mozlog
      Map<String, Object> jsonPayload = entry.getJsonPayload();
      String jbuf = null;
      if (jsonPayload != null) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(
            com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        try {
          jbuf = mapper.writeValueAsString(jsonPayload);
        } catch (JsonProcessingException exc) {
          // pass
        }
      }
      if (jbuf != null) {
        Mozlog m = Mozlog.fromJSON(jbuf);
        if (m != null) {
          e.setMozlog(m);
          state.setMozlogHint(m);
          return m.getFieldsAsJson();
        }
      }
    }

    Mozlog m = Mozlog.fromJSON(input);
    if (m != null) {
      e.setMozlog(m);
      state.setMozlogHint(m);
      return m.getFieldsAsJson();
    }
    return input;
  }

  private String stripEncapsulation(Event e, String input, ParserState state) {
    input = stripStackdriverEncapsulation(e, input, state);
    // If stripping the encapsulation returns null, just return null here to ignore the event. This
    // could occur for example of Stackdriver specific project filtering is in place.
    if (input == null) {
      return null;
    }
    input = stripMozlog(e, input, state);
    return input;
  }

  /**
   * Resolve GeoIP information from IP address string
   *
   * <p>GeoIP resolution must be enabled in the parser, or this function will always return null.
   *
   * @param ip IP address string
   * @return MaxmindDB {@link CityResponse}, or null if lookup fails
   */
  public CityResponse geoIp(String ip) {
    if (geoip == null) {
      return null;
    }
    return geoip.lookup(ip);
  }

  /**
   * Enable GeoIP resolution in the parser
   *
   * @param dbpath Path to Maxmind database, resource path or GCS URL
   */
  public void enableGeoIp(String dbpath) {
    geoip = new GeoIP(dbpath);
  }

  /**
   * Set an identity manager in the parser that can be used for lookups
   *
   * @param idmanager Initialized {@link IdentityManager}
   */
  public void setIdentityManager(IdentityManager idmanager) {
    this.idmanager = idmanager;
  }

  /**
   * Get any configured identity manager from the parser
   *
   * @return {@link IdentityManager} or null if no manager has been set in the parser
   */
  public IdentityManager getIdentityManager() {
    return idmanager;
  }

  /**
   * Parse an event
   *
   * @param input Input string
   * @return {@link Event} or null if the event should be ignored
   */
  public Event parse(String input) {
    ParserState state = new ParserState(this);

    if (input == null) {
      input = "";
    }

    Event e = new Event();
    input = stripEncapsulation(e, input, state);
    // If the strip function returns null we will just ignore the event and return null
    if (input == null) {
      return null;
    }

    for (PayloadBase p : payloads) {
      if (!p.matcher(input, state)) {
        continue;
      }
      Class<?> cls = p.getClass();
      try {
        e.setPayload(
            (PayloadBase)
                cls.getConstructor(String.class, Event.class, ParserState.class)
                    .newInstance(input, e, state));
      } catch (ReflectiveOperationException exc) {
        log.warn(exc.getMessage());
      }
      break;
    }

    return e;
  }

  /** Create new parser instance */
  public Parser() {
    log = LoggerFactory.getLogger(Parser.class);
    jf = new JacksonFactory();
    payloads = new ArrayList<PayloadBase>();
    payloads.add(new GLB());
    payloads.add(new Nginx());
    payloads.add(new SecEvent());
    payloads.add(new Cloudtrail());
    payloads.add(new GcpAudit());
    payloads.add(new BmoAudit());
    payloads.add(new OpenSSH());
    payloads.add(new Duopull());
    payloads.add(new Raw());
  }
}
