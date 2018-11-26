package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.identity.IdentityManager;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Event parser
 *
 * <p>{@link Parser} can be used to parse incoming events and generate {@link Event} objects.
 *
 * <p>On initialization the parser will also attempt to initialize the GeoIP parser that some
 * individual event parsers can utilize. See documentation for {@link GeoIP} on dependencies for
 * GeoIP lookup support.
 */
public class Parser {
  private static final long serialVersionUID = 1L;

  private final List<PayloadBase> payloads;
  private final JacksonFactory jf;
  private final Logger log;
  private final GeoIP geoip;

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

  private String stripStackdriverEncapsulation(Event e, String input) {
    try {
      JsonParser jp = jf.createJsonParser(input);
      LogEntry entry = jp.parse(LogEntry.class);
      String ret = entry.getTextPayload();
      if (ret != null && !ret.isEmpty()) {
        return ret;
      }
      Map<String, Object> jret = entry.getJsonPayload();
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

  private String stripMozlog(Event e, String input) {
    Mozlog m = Mozlog.fromJSON(input);
    if (m != null) {
      e.setMozlog(m);
      return m.getFieldsAsJson();
    }
    return input;
  }

  private String stripEncapsulation(Event e, String input) {
    input = stripStackdriverEncapsulation(e, input);
    input = stripMozlog(e, input);
    return input;
  }

  /**
   * Resolve GeoIP information from IP address string
   *
   * @param ip IP address string
   * @return MaxmindDB {@link CityResponse}, or null if lookup fails
   */
  public CityResponse geoIp(String ip) {
    return geoip.lookup(ip);
  }

  /**
   * Determine if GeoIP test database is being used
   *
   * @return True if test database is loaded by GeoIP submodule
   */
  public Boolean geoIpUsingTest() {
    return geoip.usingTest();
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
        e.setPayload(
            (PayloadBase)
                cls.getConstructor(String.class, Event.class, Parser.class)
                    .newInstance(input, e, this));
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
    geoip = new GeoIP();
    jf = new JacksonFactory();
    payloads = new ArrayList<PayloadBase>();
    payloads.add(new GLB());
    payloads.add(new SecEvent());
    payloads.add(new Cloudtrail());
    payloads.add(new OpenSSH());
    payloads.add(new Duopull());
    payloads.add(new Raw());
  }
}
