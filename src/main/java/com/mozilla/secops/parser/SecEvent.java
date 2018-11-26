package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.IOException;
import java.io.Serializable;
import org.joda.time.DateTime;

/** Payload parser for SecEvent log data */
public class SecEvent extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.secevent.SecEvent secEventData;

  private ObjectMapper getObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
    return mapper;
  }

  @Override
  public Boolean matcher(String input) {
    ObjectMapper mapper = getObjectMapper();
    com.mozilla.secops.parser.models.secevent.SecEvent d;
    try {
      d = mapper.readValue(input, com.mozilla.secops.parser.models.secevent.SecEvent.class);
    } catch (IOException exc) {
      return false;
    }
    String msg = d.getSecEventVersion();
    if (msg != null && msg.equals("secevent.model.1")) {
      return true;
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.SECEVENT;
  }

  @Override
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    if (secEventData == null) {
      return null;
    }
    switch (property) {
      case SECEVENT_ACTION:
        return secEventData.getAction();
      case SECEVENT_SOURCEADDRESS:
        return secEventData.getSourceAddress();
      case SECEVENT_ACCOUNTID:
        return secEventData.getActorAccountId();
      case SECEVENT_EMAILRECIPIENT:
        return secEventData.getEmailRecipient();
      case SECEVENT_SMSRECIPIENT:
        return secEventData.getSmsRecipient();
    }
    return null;
  }

  /**
   * Fetch parsed secevent data
   *
   * @return SecEvent data
   */
  public com.mozilla.secops.parser.models.secevent.SecEvent getSecEventData() {
    return secEventData;
  }

  /** Construct matcher object. */
  public SecEvent() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param p Parser instance.
   */
  public SecEvent(String input, Event e, Parser p) {
    ObjectMapper mapper = getObjectMapper();
    try {
      secEventData =
          mapper.readValue(input, com.mozilla.secops.parser.models.secevent.SecEvent.class);
      if (secEventData == null) {
        return;
      }
    } catch (IOException exc) {
      return;
    }

    // If a timestamp value is set in the event body, use that for the event timestamp
    DateTime ts = secEventData.getTimestamp();
    if (ts != null) {
      e.setTimestamp(ts);
    }
  }
}
