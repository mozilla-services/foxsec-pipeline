package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.models.cloudtrail.CloudtrailEvent;
import com.mozilla.secops.parser.models.cloudtrail.UserIdentity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/** Payload parser for Cloudtrail events */
public class Cloudtrail extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private ObjectMapper mapper;

  private CloudtrailEvent event;

  private String sourceAddressCity;
  private String sourceAddressCountry;

  @Override
  public Boolean matcher(String input, ParserState state) {
    try {
      if (parseInput(input) != null) {
        return true;
      }
    } catch (IOException exc) {
      // pass
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.CLOUDTRAIL;
  }

  /** Construct matcher object. */
  public Cloudtrail() {
    mapper = getObjectMapper();
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param p Parser instance.
   */
  public Cloudtrail(String input, Event e, ParserState state) {
    mapper = getObjectMapper();
    try {
      event = parseInput(input);
      if (isAuthEvent()) {
        Normalized n = e.getNormalized();
        n.setType(Normalized.Type.AUTH);
        n.setSubjectUser(getUser());
        n.setSourceAddress(getSourceAddress());
        n.setObject(event.getRecipientAccountId());

        // TODO: Consider moving identity management into Normalized

        // If we have an instance of IdentityManager in the parser, see if we can
        // also set the resolved subject identity
        IdentityManager mgr = state.getParser().getIdentityManager();
        if (mgr != null) {
          String resId = mgr.lookupAlias(getUser());
          if (resId != null) {
            n.setSubjectUserIdentity(resId);
          }

          Map<String, String> m = mgr.getAwsAccountMap();
          String accountName = m.get(event.getRecipientAccountId());
          if (accountName != null) {
            n.setObject(accountName);
          }
        }

        if (getSourceAddress() != null) {
          CityResponse cr = state.getParser().geoIp(getSourceAddress());
          if (cr != null) {
            sourceAddressCity = cr.getCity().getName();
            sourceAddressCountry = cr.getCountry().getIsoCode();
            n.setSourceAddressCity(sourceAddressCity);
            n.setSourceAddressCountry(sourceAddressCountry);
          }
        }
      }
    } catch (IOException exc) {
      return;
    }
  }

  private CloudtrailEvent parseInput(String input) throws IOException {
    try {
      JacksonFactory jfmatcher = new JacksonFactory();
      JsonParser jp = jfmatcher.createJsonParser(input);
      LogEntry entry = jp.parse(LogEntry.class);
      Map<String, Object> m = entry.getJsonPayload();
      if (m != null) {
        // XXX Unwrap the json payload within the log entry into a string
        // that can then be parsed by ObjectMapper into CloudtrailEvent. This
        // should probably be done within Parser.
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        mapper.writeValue(buf, m);
        input = buf.toString();
      }
    } catch (IOException exc) {
      // pass
    } catch (IllegalArgumentException exc) {
      // pass
    }

    try {
      CloudtrailEvent _event = mapper.readValue(input, CloudtrailEvent.class);
      if (_event.getEventVersion() != null) {
        return _event;
      }
    } catch (IOException exc) {
      throw exc;
    }

    return null;
  }

  private ObjectMapper getObjectMapper() {
    ObjectMapper _mapper = new ObjectMapper();
    _mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    return _mapper;
  }

  /**
   * Get username
   *
   * @return Username
   */
  public String getUser() {
    return event.getIdentityName();
  }

  /**
   * Get source address
   *
   * @return Source address
   */
  public String getSourceAddress() {
    return event.getSourceIPAddress();
  }

  /**
   * Get source address city field
   *
   * @return Source address city string
   */
  public String getSourceAddressCity() {
    return sourceAddressCity;
  }

  /**
   * Get source address country field
   *
   * @return Source address country string
   */
  public String getSourceAddressCountry() {
    return sourceAddressCountry;
  }

  private Boolean isAuthEvent() {
    if (event.getEventName() == null) {
      return false;
    }

    if (event.getEventName().equals("ConsoleLogin")) {
      if (event.getEventType() != null
          && event.getEventType().equals("AwsConsoleSignIn")
          && event.getResponseElementsValue("ConsoleLogin") != null
          && event.getResponseElementsValue("ConsoleLogin").equals("Success")) {
        return true;
      }
    }

    if (event.getEventName().equals("AssumeRole")) {
      if (event.getUserType() != null
          && event.getUserType().equals("IAMUser")
          && event.getErrorCode() == null) {
        return true;
      }
    }
    return false;
  }

  @Override
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    UserIdentity ui = event.getUserIdentity();
    switch (property) {
      case CLOUDTRAIL_EVENTNAME:
        return event.getEventName();
      case CLOUDTRAIL_EVENTSOURCE:
        return event.getEventSource();
      case CLOUDTRAIL_ACCOUNTID:
        return event.getRecipientAccountId();
      case CLOUDTRAIL_INVOKEDBY:
        if (ui == null) {
          return null;
        }
        return ui.getInvokedBy();
      case CLOUDTRAIL_MFA:
        if (ui == null) {
          return null;
        }
        return ui.getMFAAuthenticated();
    }
    return null;
  }

  /**
   * Utility method for returning the resource the event was acting on, used for adding context to
   * an {@link com.mozilla.secops.alert.Alert}.
   *
   * @param resource Resource selector.
   * @return Value of the resource selector.
   */
  public String getResource(String resource) {
    switch (resource) {
      case "requestParameters.userName":
        HashMap<String, Object> rp = event.getRequestParameters();
        Object u = rp.get("userName");
        if (u == null) {
          return null;
        }
        return (String) u;
    }
    return null;
  }
}
