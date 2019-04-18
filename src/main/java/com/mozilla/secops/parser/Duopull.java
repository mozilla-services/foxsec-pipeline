package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;
import org.joda.time.DateTime;

/**
 * Payload parser for Duopull audit trail log data
 *
 * <p>See also https://github.com/mozilla-services/duopull-lambda
 */
public class Duopull extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.duopull.Duopull duoPullData;

  @Override
  public Boolean matcher(String input, ParserState state) {
    ObjectMapper mapper = new ObjectMapper();
    com.mozilla.secops.parser.models.duopull.Duopull d;
    try {
      d = mapper.readValue(input, com.mozilla.secops.parser.models.duopull.Duopull.class);
    } catch (IOException exc) {
      return false;
    }
    String msg = d.getMsg();
    if (msg != null && msg.equals("duopull event")) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.DUOPULL;
  }

  /**
   * Fetch parsed duopull data
   *
   * @return Duopull data
   */
  @JsonProperty("duopull_data")
  public com.mozilla.secops.parser.models.duopull.Duopull getDuopullData() {
    return duoPullData;
  }

  /**
   * Set duopull data element
   *
   * @param data Duopull data element
   */
  public void setDuopullData(com.mozilla.secops.parser.models.duopull.Duopull data) {
    duoPullData = data;
  }

  /** Construct matcher object. */
  public Duopull() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Duopull(String input, Event e, ParserState state) {
    ObjectMapper mapper = new ObjectMapper();
    try {
      duoPullData = mapper.readValue(input, com.mozilla.secops.parser.models.duopull.Duopull.class);
      if (duoPullData.getEventTimestamp() != null) {
        e.setTimestamp(new DateTime(duoPullData.getEventTimestamp() * 1000));
      }
    } catch (IOException exc) {
      return;
    }
  }
}
