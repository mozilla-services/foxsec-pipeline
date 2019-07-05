package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.identity.IdentityManager;
import java.io.IOException;
import java.io.Serializable;
import org.joda.time.DateTime;

/**
 * Payload parser for Duopull audit trail log data
 *
 * <p>See also https://github.com/mozilla-services/duopull-lambda
 */
public class Duopull extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private static final String DUO_OBJECT = "duo";

  private static final String ADMIN_LOGIN_EVENT = "admin_login";

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

      // Create Normalized AUTH event for admin logins
      if (duoPullData.getEventAction() != null
          && duoPullData.getEventAction().equals(ADMIN_LOGIN_EVENT)) {
        String user = duoPullData.getEventUsername();
        String sourceAddr = duoPullData.getEventDescriptionIpAddress();
        if (sourceAddr != null) {
          setSourceAddress(sourceAddr, state, e.getNormalized());
        }

        Normalized n = e.getNormalized();
        n.addType(Normalized.Type.AUTH);
        n.setSubjectUser(user);
        n.setObject(String.format("duo_%s", duoPullData.getEventAction()));

        // If we have an instance of IdentityManager in the parser, see if we can
        // also set the resolved subject identity
        IdentityManager mgr = state.getParser().getIdentityManager();
        if (mgr != null) {
          String resId = mgr.lookupAlias(user);
          if (resId != null) {
            n.setSubjectUserIdentity(resId);
          }
        }
      }
    } catch (IOException exc) {
      return;
    }
  }
}
