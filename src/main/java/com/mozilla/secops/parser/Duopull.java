package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;

/**
 * Payload parser for Duopull audit trail log data
 *
 * <p>See also https://github.com/mozilla-services/duopull-lambda
 */
public class Duopull extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.duopull.Duopull duoPullData;

  @Override
  public Boolean matcher(String input) {
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
  public Payload.PayloadType getType() {
    return Payload.PayloadType.DUOPULL;
  }

  /**
   * Fetch parsed duopull data
   *
   * @return Duopull data
   */
  public com.mozilla.secops.parser.models.duopull.Duopull getDuopullData() {
    return duoPullData;
  }

  /** Construct matcher object. */
  public Duopull() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param p Parser instance.
   */
  public Duopull(String input, Event e, Parser p) {
    ObjectMapper mapper = new ObjectMapper();
    try {
      duoPullData = mapper.readValue(input, com.mozilla.secops.parser.models.duopull.Duopull.class);
    } catch (IOException exc) {
      return;
    }
  }
}
