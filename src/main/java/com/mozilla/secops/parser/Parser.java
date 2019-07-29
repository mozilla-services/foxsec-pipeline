package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.logging.v2.model.MonitoredResource;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.models.cloudwatch.CloudWatchEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
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
  private final ObjectMapper mapper;
  private final JacksonFactory googleJacksonFactory;
  private final Logger log;
  private final ParserCfg cfg;
  private GeoIP geoip;

  public static final String SYSLOG_TS_RE = "\\S{3} {1,2}\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}";

  private IdentityManager idmanager;

  /**
   * Given an interable of events, return the latest timestamp
   *
   * @param events Event list
   * @return Latest timestamp in event set
   */
  public static DateTime getLatestTimestamp(Iterable<Event> events) {
    DateTime max = null;
    for (Event e : events) {
      if (max == null) {
        max = e.getTimestamp();
      } else {
        if (max.isBefore(e.getTimestamp())) {
          max = e.getTimestamp();
        }
      }
    }
    return max;
  }

  /**
   * Parse syslog timestamp date time string and return a {@link DateTime} object.
   *
   * @param in Input string
   * @return Parsed {@link DateTime}, null if string could not be parsed
   */
  public static DateTime parseSyslogTs(String in) {
    try {
      // "Apr 13 xx:xx:xx"
      return DateTime.parse(in, DateTimeFormat.forPattern("MMM dd HH:mm:ss"));
    } catch (IllegalArgumentException e) {
      // "Feb  8 xx:xx:xx"
      try {
        return DateTime.parse(in, DateTimeFormat.forPattern("MMM  d HH:mm:ss"));
      } catch (IllegalArgumentException exc) {
        return null;
      }
    }
  }

  /**
   * Parse syslog timestamp date time string and return a {@link DateTime} object using {@link
   * #parseSyslogTs(String)}, and then correct the year if the parsed timestamp is further than
   * three days from the event timestamp.
   *
   * @param in Input string
   * @param e {@link Event}
   * @return Parsed {@link DateTime}, null if string could not be parsed
   */
  public static DateTime parseAndCorrectSyslogTs(String in, Event e) {
    DateTime et = parseSyslogTs(in);
    if (et == null) {
      return null;
    }

    if (et.isAfter(e.getTimestamp().minusDays(3)) && et.isBefore(e.getTimestamp().plusDays(3))) {
      return et;
    }
    return et.withYear(e.getTimestamp().year().get());
  }

  /**
   * Parse an ISO8601 date string and return a {@link DateTime} object.
   *
   * @param in Input string
   * @return Parsed {@link DateTime}, null if string could not be parsed
   */
  public static DateTime parseISO8601(String in) {
    DateTimeFormatter fmt = ISODateTimeFormat.dateTimeParser();
    try {
      return fmt.parseDateTime(in);
    } catch (IllegalArgumentException exc) {
      return null;
    }
  }

  /**
   * Apply any configured XFF address selector to the specified input string
   *
   * <p>If no XFF address selector has been configured in the parser configuration, and the input
   * contains multiple XFF style addresses, the last address is returned.
   *
   * @param input Input string
   * @return Results of address selector application
   */
  public String applyXffAddressSelector(String input) throws IllegalArgumentException {
    if (input == null) {
      return null;
    }

    CidrUtil c = cfg.getXffAddressSelectorAsCidrUtil();

    String[] parts = parseXForwardedFor(input);
    if (parts == null) {
      // Input was not formatted correctly or was not an IP address
      return null;
    }

    if (parts.length <= 1) {
      // Just a single element, return the input as is
      return input;
    }

    if (c == null) {
      // No selectors specified but we had multiple addresses, return the last one
      return parts[parts.length - 1];
    }

    for (int i = parts.length - 1; i >= 0; i--) {
      if (c.contains(parts[i])) {
        continue;
      } else {
        return parts[i];
      }
    }
    return parts[parts.length - 1];
  }

  /**
   * Utility function to convert a JSON string into the desired map type
   *
   * @param input Input JSON
   * @return HashMap
   */
  public static <T, U> HashMap<T, U> convertJsonToMap(String input) {
    ObjectMapper mapper = new ObjectMapper();
    HashMap<T, U> fields = new HashMap<T, U>();
    try {
      fields = mapper.readValue(input, new TypeReference<Map<T, U>>() {});
    } catch (IOException exc) {
      return null;
    }
    return fields;
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
      if (entry.getTimestamp() != null) {
        DateTime et = Parser.parseISO8601(entry.getTimestamp());
        if (et != null) {
          e.setTimestamp(et);
        }
      }

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
        try {
          jbuf = mapper.writeValueAsString(jsonPayload);
        } catch (JsonProcessingException exc) {
          // pass
        }
      }
      if (jbuf != null) {
        Mozlog m = Mozlog.fromJSON(jbuf, mapper);
        if (m != null) {
          e.setMozlog(m);
          state.setMozlogHint(m);
          return m.getFieldsAsJson();
        }
      }
    }

    Mozlog m = Mozlog.fromJSON(input, mapper);
    if (m != null) {
      e.setMozlog(m);
      state.setMozlogHint(m);
      return m.getFieldsAsJson();
    }
    return input;
  }

  private String stripCloudWatch(Event e, String input, ParserState state) {
    try {
      CloudWatchEvent cwe = mapper.readValue(input, CloudWatchEvent.class);
      if (cwe.getDetail() == null || cwe.getDetailType() == null || cwe.getAccount() == null) {
        return input;
      }
      state.setCloudWatchEvent(cwe);
      return mapper.writeValueAsString(cwe.getDetail());
    } catch (IOException exc) {
      // pass
    }
    // If the input data could not be converted into a CloudWatch Event just return it as is
    return input;
  }

  private String stripEncapsulation(Event e, String input, ParserState state) {
    input = stripStackdriverEncapsulation(e, input, state);
    // If stripping the encapsulation returns null, just return null here to ignore the event. This
    // could occur for example of Stackdriver specific project filtering is in place.
    if (input == null) {
      return null;
    }
    input = stripCloudWatch(e, input, state);
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
    return geoip.lookupCity(ip);
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
    String fm = cfg.getParserFastMatcher();
    // If a fast matcher is set, test the input immediately against it and discard the
    // event if it does not match. A special case exists here to always pass messages that
    // appear to be configuration ticks from CompositeInput.
    if (fm != null && input != null) {
      if (!input.contains(fm) && !input.contains("configuration_tick")) {
        return null;
      }
    }

    ParserState state = new ParserState(this);
    state.setGoogleJacksonFactory(googleJacksonFactory);

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

  /**
   * Create new parser instance with specified configuration
   *
   * @param cfg {@link ParserCfg}
   */
  public Parser(ParserCfg cfg) {
    log = LoggerFactory.getLogger(Parser.class);
    jf = new JacksonFactory();

    mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    // Not all Mozlog implementations use lower case field names, and we will reuse this mapper
    // for Mozlog conversion
    mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
    // Allows for null values in the JsonPayload in a LogEntry
    mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    googleJacksonFactory = new JacksonFactory();

    this.cfg = cfg;
    if (cfg.getMaxmindCityDbPath() != null || cfg.getMaxmindIspDbPath() != null) {
      geoip = new GeoIP(cfg.getMaxmindCityDbPath(), cfg.getMaxmindIspDbPath());
    }
    payloads = new ArrayList<PayloadBase>();
    payloads.add(new GLB());
    payloads.add(new Nginx());
    payloads.add(new SecEvent());
    payloads.add(new Cloudtrail());
    payloads.add(new GcpAudit());
    payloads.add(new ApacheCombined());
    payloads.add(new BmoAudit());
    payloads.add(new FxaAuth());
    payloads.add(new Taskcluster());
    payloads.add(new AmoDocker());
    payloads.add(new OpenSSH());
    payloads.add(new Duopull());
    payloads.add(new Alert());
    payloads.add(new GuardDuty());
    payloads.add(new ETDBeta());
    payloads.add(new CfgTick());
    payloads.add(new Raw());

    if (cfg.getIdentityManagerPath() != null) {
      try {
        IdentityManager mgr = IdentityManager.load(cfg.getIdentityManagerPath());
        setIdentityManager(mgr);
      } catch (IOException exc) {
        log.error("could not load identity manager within Parser: {}", exc.getMessage());
      }
    }
  }

  /** Create new parser instance with default configuration */
  public Parser() {
    this(new ParserCfg());
  }
}
