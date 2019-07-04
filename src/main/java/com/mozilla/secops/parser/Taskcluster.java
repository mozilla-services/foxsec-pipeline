package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;
import java.util.regex.Pattern;

/** Payload parser for Taskcluster log data */
public class Taskcluster extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.taskcluster.Taskcluster data;
  private String subject;

  private final Pattern emailPattern;

  @Override
  public Boolean matcher(String input, ParserState state) {
    ObjectMapper mapper = new ObjectMapper();
    com.mozilla.secops.parser.models.taskcluster.Taskcluster d;
    try {
      d = mapper.readValue(input, com.mozilla.secops.parser.models.taskcluster.Taskcluster.class);
    } catch (IOException exc) {
      return false;
    }
    Mozlog m = state.getMozlogHint();
    if (m == null) {
      return false;
    }
    String logger = m.getLogger();
    if (logger == null) {
      return false;
    }
    if (logger.startsWith("taskcluster.")) {
      return true;
    }
    return false;
  }

  /**
   * Get resolved subject ID
   *
   * @return Subject identifier, or null if unset
   */
  public String getResolvedSubject() {
    return subject;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.TASKCLUSTER;
  }

  private Boolean processClientIdAuth0(String[] parts) {
    if (!parts[0].equals("mozilla-auth0")) {
      return false;
    }
    String[] ps = parts[1].split("\\|");
    if (ps.length != 3) {
      return false;
    }
    if (ps[0].equals("ad") && ps[1].equals("Mozilla-LDAP")) {
      subject = ps[2];
      return true;
    }
    return false;
  }

  private Boolean processClientIdEmail(String[] parts) {
    if (!parts[0].equals("email")) {
      return false;
    }
    if (emailPattern.matcher(parts[1]).matches()) {
      subject = parts[1];
      return true;
    }
    return false;
  }

  private Boolean processClientIdLdap(String[] parts) {
    if (!parts[0].equals("mozilla-ldap")) {
      return false;
    }
    if (emailPattern.matcher(parts[1]).matches()) {
      subject = parts[1];
      return true;
    }
    return false;
  }

  /**
   * Extract identity information from the client ID
   *
   * <p>See also https://docs.taskcluster.net/docs/manual/design/namespaces#clients
   */
  private void processClientId() {
    String idcomp = data.getClientId();
    if (idcomp == null) {
      return;
    }
    String[] parts = idcomp.split("/");
    if (parts.length < 2) {
      return;
    }
    if (processClientIdEmail(parts)) {
      return;
    } else if (processClientIdAuth0(parts)) {
      return;
    } else {
      processClientIdLdap(parts);
    }
  }

  /**
   * Fetch parsed Taskcluster data
   *
   * @return Taskcluster data
   */
  @JsonProperty("taskcluster_data")
  public com.mozilla.secops.parser.models.taskcluster.Taskcluster getTaskclusterData() {
    return data;
  }

  /**
   * Set Taskcluster data element
   *
   * @param data Taskcluster data element
   */
  public void setTaskclusterData(com.mozilla.secops.parser.models.taskcluster.Taskcluster data) {
    this.data = data;
  }

  /** Construct matcher object. */
  public Taskcluster() {
    emailPattern = null;
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Taskcluster(String input, Event e, ParserState state) {
    emailPattern =
        Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);

    ObjectMapper mapper = new ObjectMapper();
    try {
      data =
          mapper.readValue(input, com.mozilla.secops.parser.models.taskcluster.Taskcluster.class);
    } catch (IOException exc) {
      return;
    }

    String sourceAddr = data.getSourceIp();
    if (sourceAddr != null) {
      setSourceAddress(sourceAddr, state, e.getNormalized());
    }

    processClientId();

    // If we were able to get a resolved subject ID, and we have a source IP address then add
    // normalized session information to the event
    if ((subject != null) && (getSourceAddress() != null)) {
      Normalized n = e.getNormalized();
      n.addType(Normalized.Type.AUTH_SESSION);
      n.setSubjectUser(subject);
      if (data.getResource() != null) {
        n.setObject("taskcluster-" + data.getResource());
      } else {
        n.setObject("taskcluster");
      }
      return;
    }
  }
}
