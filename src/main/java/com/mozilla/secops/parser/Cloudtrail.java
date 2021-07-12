package com.mozilla.secops.parser;

import com.amazonaws.arn.Arn;
import com.amazonaws.arn.ArnResource;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.Normalized.StatusTag;
import com.mozilla.secops.parser.models.cloudtrail.CloudtrailEvent;
import com.mozilla.secops.parser.models.cloudtrail.UserIdentity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import org.joda.time.DateTime;

/** Payload parser for Cloudtrail events */
public class Cloudtrail extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  /* Event Types */
  private static final String SWITCH_ROLE = "SwitchRole";
  private static final String ASSUME_ROLE = "AssumeRole";
  private static final String AWS_CONSOLE_SIGNIN = "AwsConsoleSignIn";
  private static final String GET_SESSION_TOKEN = "GetSessionToken";

  /* User Types */
  private static final String IAM_USER = "IAMUser";
  private static final String AWS_ACCOUNT = "AWSAccount";

  /* Response Elements */
  private static final String SUCCESS = "Success";
  private static final String CONSOLE_LOGIN = "ConsoleLogin";

  private CloudtrailEvent event;

  @Override
  public Boolean matcher(String input, ParserState state) {
    try {
      if (parseInput(input, state) != null) {
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
  public Cloudtrail() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Cloudtrail(String input, Event e, ParserState state) {
    try {
      event = parseInput(input, state);
      if (event.getEventTime() != null) {
        DateTime t = Parser.parseISO8601(event.getEventTime());
        if (t != null) {
          e.setTimestamp(t);
        }
      }
      Normalized n = e.getNormalized();
      // If we have a source address field in the model, pull that into the inherited field
      if (event.getSourceIPAddress() != null) {
        setSourceAddress(event.getSourceIPAddress(), state, n);
      }

      n.setReferenceID(event.getEventID());

      if (isAuthEvent()) {
        n.addType(Normalized.Type.AUTH);
        n.setSubjectUser(getUser());
        n.setObject(event.getRecipientAccountId());

        // if this is not an event for an IAMUser than tag
        // the event as needing fix up
        if (isAssumeRoleFromAnotherAccount()) {
          n.setStatusTag(StatusTag.REQUIRES_SUBJECT_USER_FIXUP);
        }

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
      }
    } catch (IOException exc) {
      return;
    }
  }

  private CloudtrailEvent parseInput(String input, ParserState state) throws IOException {
    GsonFactory jfmatcher = state.getGoogleJacksonFactory();
    try (JsonParser jp = jfmatcher.createJsonParser(input); ) {
      LogEntry entry = jp.parse(LogEntry.class);
      Map<String, Object> m = entry.getJsonPayload();
      if (m != null) {
        // XXX Unwrap the json payload within the log entry into a string
        // that can then be parsed by ObjectMapper into CloudtrailEvent. This
        // should probably be done within Parser.
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        state.getObjectMapper().writeValue(buf, m);
        input = buf.toString();
      }
    } catch (IOException | IllegalArgumentException exc) {
      // pass
    }

    try {
      CloudtrailEvent _event = state.getObjectMapper().readValue(input, CloudtrailEvent.class);
      if (_event == null) {
        return null;
      }
      if (_event.getEventVersion() != null) {
        return _event;
      }
    } catch (IOException exc) {
      throw exc;
    }

    return null;
  }

  /**
   * Get username
   *
   * @return Username
   */
  public String getUser() {
    // if this is a SwitchRole event for a role not in
    // the account then use the switchFrom field instead
    // of userIdentity
    if (isSwitchRoleEvent()) {
      String switchFrom = getSwitchFrom();
      if (switchFrom != null) {
        try {
          Arn arn = Arn.fromString(switchFrom);
          ArnResource arnResource = arn.getResource();
          if (arnResource.getResourceType().equals("user")) {
            return arnResource.getResource();
          }
        } catch (IllegalArgumentException e) {
          // if invalid arn, just use the normal identity
        }
      }
    }
    return event.getIdentityName();
  }

  private Boolean isAuthEvent() {
    if (event.getEventName() == null) {
      return false;
    }

    if (event.getEventName().equals(CONSOLE_LOGIN)) {
      if (event.getEventType() != null
          && event.getEventType().equals(AWS_CONSOLE_SIGNIN)
          && event.getResponseElementsValue(CONSOLE_LOGIN) != null
          && event.getResponseElementsValue(CONSOLE_LOGIN).equals(SUCCESS)) {
        return true;
      }
    }

    if (event.getEventName().equals(GET_SESSION_TOKEN)) {
      if (event.getUserType() != null
          && event.getUserType().equals(IAM_USER)
          && event.getErrorCode() == null) {
        return true;
      }
    }

    // consider events from both an IAMUser as well as
    // another account to be auth events
    // those from another account can be fixed up later
    if (event.getEventName().equals(ASSUME_ROLE)) {
      if (event.getUserType() != null
          && (event.getUserType().equals(IAM_USER))
          && event.getErrorCode() == null) {
        return true;
      }
    }

    return isAssumeRoleFromAnotherAccount() || isSwitchRoleEvent();
  }

  private boolean isAssumeRoleFromAnotherAccount() {
    if (event.getEventName().equals(ASSUME_ROLE)) {
      if (event.getUserType() != null
          && event.getUserType().equals(AWS_ACCOUNT)
          && event.getErrorCode() == null) {
        return true;
      }
    }
    return false;
  }

  private boolean isSwitchRoleEvent() {
    if (event.getEventName().equals(SWITCH_ROLE)) {
      if (event.getEventType() != null
          && event.getEventType().equals(AWS_CONSOLE_SIGNIN)
          && event.getResponseElementsValue(SWITCH_ROLE) != null
          && event.getResponseElementsValue(SWITCH_ROLE).equals(SUCCESS)) {
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

  private String getSwitchFrom() {
    Object switchFrom = event.getAdditionalEventDataValue("SwitchFrom");
    if (switchFrom != null) {
      return (String) switchFrom;
    }
    return null;
  }

  /**
   * Returns the shared event id of the cloudtrail event
   *
   * @return value of sharedEventID field
   */
  public String getSharedEventID() {
    return event.getSharedEventID();
  }

  /**
   * Returns the event id of the cloudtrail event
   *
   * @return value of eventID field
   */
  public String getEventID() {
    return event.getEventID();
  }

  /**
   * Utility method for returning the resource the event was acting on, used for adding context to
   * an {@link com.mozilla.secops.alert.Alert}.
   *
   * @param resource Resource selector.
   * @return Value of the resource selector.
   */
  public String getResource(String resource) {
    HashMap<String, Object> rp = event.getRequestParameters();
    switch (resource) {
      case "requestParameters.userName":
        Object u = rp.get("userName");
        if (u == null) {
          return null;
        }
        return (String) u;
      case "requestParameters.roleArn":
        Object r = rp.get("roleArn");
        if (r == null) {
          return null;
        }
        return (String) r;
    }
    return null;
  }
}
