package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.models.auth0.LogEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.joda.time.DateTime;

/** Payload parser for Auth0 logs */
public class Auth0 extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private ObjectMapper mapper;

  private LogEvent event;

  private static ArrayList<String> AuthTypes;

  // List of auth0 type codes that are auth events
  // https://auth0.com/docs/logs#log-data-event-listing
  static {
    AuthTypes = new ArrayList<String>();
    AuthTypes.add("s");
    AuthTypes.add("ssa");
    AuthTypes.add("seacft");
    AuthTypes.add("seoobft");
    AuthTypes.add("seotpft");
    AuthTypes.add("sepft");
    AuthTypes.add("scoa");
  }

  private static Map<String, String> TypeMap;

  // Mapping of auth0 type codes to there name
  // https://auth0.com/docs/logs#log-data-event-listing
  static {
    TypeMap = new HashMap<String, String>();
    TypeMap.put("s", "Success Login");
    TypeMap.put("ssa", "Success Silent Auth");
    TypeMap.put("fsa", "Failed Silent Auth");
    TypeMap.put("seacft", "Success Exchange (Authorization Code for Access Token)");
    TypeMap.put("feacft", "Failed Exchange (Authorization Code for Access Token)");
    TypeMap.put("seccft", "Success Exchange (Client Credentials for Access Token)");
    TypeMap.put("feccft", "Failed Exchange (Client Credentials for Access Token)");
    TypeMap.put("sepft", "Success Exchange (Password for Access Token)");
    TypeMap.put("fepft", "Failed Exchange (Password for Access Token)");
    TypeMap.put("seoobft", "Successful Exchange (Password and OOB Challenge for Access Token)");
    TypeMap.put("feoobft", "Failed exchange (Password and OOB Challenge for Access Token)");
    TypeMap.put("seotpft", "Successful exchange (Password and OTP Challenge for Access Token)");
    TypeMap.put("feotpft", "Failed exchange (Password and OTP Challenge for Access Token)");
    TypeMap.put("f", "Failed Login");
    TypeMap.put("w", "Warnings During Login");
    TypeMap.put("du", "Deleted User");
    TypeMap.put("fu", "Failed Login (invalid email/username)");
    TypeMap.put("fp", "Failed Login (wrong password)");
    TypeMap.put("fc", "Failed by Connector");
    TypeMap.put("fco", "Failed by CORS");
    TypeMap.put("con", "Connector Online");
    TypeMap.put("coff", "Connector Offline");
    TypeMap.put("fcpro", "Failed Connector Provisioning");
    TypeMap.put("ss", "Success Signup");
    TypeMap.put("fs", "Failed Signup");
    TypeMap.put("cs", "Code Sent");
    TypeMap.put("cls", "Code/Link Sent");
    TypeMap.put("sv", "Success Verification Email");
    TypeMap.put("fv", "Failed Verification Email");
    TypeMap.put("scp", "Success Change Password");
    TypeMap.put("fcp", "Failed Change Password");
    TypeMap.put("sce", "Success Change Email");
    TypeMap.put("fce", "Failed Change Email");
    TypeMap.put("scu", "Success Change Username");
    TypeMap.put("fcu", "Failed Change Username");
    TypeMap.put("scpn", "Success Change Phone Number");
    TypeMap.put("fcpn", "Failed Change Phone Number");
    TypeMap.put("svr", "Success Verification Email Request");
    TypeMap.put("fvr", "Failed Verification Email Request");
    TypeMap.put("scpr", "Success Change Password Request");
    TypeMap.put("fcpr", "Failed Change Password Request");
    TypeMap.put("fn", "Failed Sending Notification");
    TypeMap.put("sapi", "API Operation");
    TypeMap.put("fapi", "Failed API Operation");
    TypeMap.put("limit_wc", "Blocked Account");
    TypeMap.put("limit_mu", "Blocked IP Address");
    TypeMap.put("limit_ui", "Too Many Calls to /userinfo");
    TypeMap.put("api_limit", "Rate Limit On API");
    TypeMap.put("sdu", "Successful User Deletion");
    TypeMap.put("fdu", "Failed User Deletion");
    TypeMap.put("slo", "Success Logout");
    TypeMap.put("flo", "Failed Logout");
    TypeMap.put("sd", "Success Delegation");
    TypeMap.put("fd", "Failed Delegation");
    TypeMap.put("fcoa", "Failed Cross Origin Authentication");
    TypeMap.put("scoa", "Success Cross Origin Authentication");
  };

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
    return Payload.PayloadType.AUTH0;
  }

  /** Construct matcher object. */
  public Auth0() {
    mapper = getObjectMapper();
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Auth0(String input, Event e, ParserState state) {
    mapper = getObjectMapper();
    try {
      event = parseInput(input);
      if (event.getDate() != null) {
        e.setTimestamp(new DateTime(event.getDate().getTime()));
      }

      // If we have a source address field in the model, pull that into the inherited field
      if (event.getIP() != null) {
        setSourceAddress(event.getIP(), state, e.getNormalized());
      }

      if (isAuthEvent()) {
        Normalized n = e.getNormalized();
        n.addType(Normalized.Type.AUTH);

        n.setSubjectUser(getUsername());
        n.setObject(event.getClientName());

        // If we have an instance of IdentityManager in the parser, see if we can
        // also set the resolved subject identity
        IdentityManager mgr = state.getParser().getIdentityManager();
        if (mgr != null) {
          String resId = mgr.lookupAlias(getUsername());
          if (resId != null) {
            n.setSubjectUserIdentity(resId);
          }
        }
      }
    } catch (IOException exc) {
      return;
    }
  }

  private LogEvent parseInput(String input) throws IOException {
    JsonParser jp = null;
    try {
      JacksonFactory jfmatcher = new JacksonFactory();
      jp = jfmatcher.createJsonParser(input);
      LogEntry entry = jp.parse(LogEntry.class);
      Map<String, Object> m = entry.getJsonPayload();
      if (m != null) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        mapper.writeValue(buf, m);
        input = buf.toString();
      }
    } catch (IOException exc) {
      // pass
    } catch (IllegalArgumentException exc) {
      // pass
    } finally {
      if (jp != null) {
        jp.close();
      }
    }

    try {
      LogEvent _event = mapper.readValue(input, LogEvent.class);
      if (_event.getClientId() != null) {
        return _event;
      }
    } catch (IOException exc) {
      throw exc;
    }

    return null;
  }

  /**
   * Return username within event
   *
   * @return Username as string, or null if it can't be found.
   */
  public String getUsername() {
    if (event.getDetails() != null && event.getDetails().containsKey("prompts")) {
      if (event.getDetails().get("prompts") instanceof ArrayList) {
        ArrayList<?> prompts = (ArrayList<?>) event.getDetails().get("prompts");
        for (int i = 0; i < prompts.size(); i++) {
          Object prompt = prompts.get(i);
          if (prompt instanceof HashMap) {
            // The compiler cannot check that the parameter of `<String, Object>` is actually safe,
            // therefore it will always throw a warning here even though it is done in a safe
            // manner.
            @SuppressWarnings("unchecked")
            HashMap<String, Object> promptValue = (HashMap<String, Object>) prompt;
            if (promptValue.containsKey("user_name")) {
              return (String) promptValue.get("user_name");
            }
          }
        }
      }
    }
    return null;
  }

  private Boolean isAuthEvent() {
    if (event.getType() == null) {
      return false;
    }
    for (String type : AuthTypes) {
      if (event.getType().equals(type)) {
        return true;
      }
    }
    return false;
  }

  private ObjectMapper getObjectMapper() {
    ObjectMapper _mapper = new ObjectMapper();
    // Auth0 is known to add new fields
    _mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    // Allows for null values in the JsonPayload in a LogEntry when mapping to a Map<String, Object>
    _mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
    return _mapper;
  }

  /**
   * Return true if Auth0 event's client id is in the passed in list of client ids
   *
   * @param clientIds list of client ids to check for
   * @return True if client id is in clientIds
   */
  public Boolean hasClientIdIn(String[] clientIds) {
    if (clientIds == null || event.getClientId() == null) {
      return false;
    }
    for (String clientId : clientIds) {
      if (event.getClientId().equals(clientId)) {
        return true;
      }
    }
    return false;
  }
}
