package com.mozilla.secops.parser;

import com.mozilla.secops.identity.IdentityManager;
import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.joda.time.DateTime;

/** Payload parser for OpenSSH log data */
public class OpenSSH extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String matchRe = "^" + Parser.SYSLOG_TS_RE + " \\S+ \\S*sshd\\[\\d+\\]: .+";
  private Pattern pattRe;

  private final String authAcceptedRe =
      "("
          + Parser.SYSLOG_TS_RE
          + ") (\\S+) sshd\\[\\d+\\]: Accepted (\\S+) for (\\S+) from (\\S+) "
          + "port (\\d+).*";
  private Pattern pattAuthAcceptedRe;

  private String user;
  private String authMethod;
  private String hostname;

  @Override
  public Boolean matcher(String input, ParserState state) {
    Matcher mat = pattRe.matcher(input);
    if (mat.matches()) {
      return true;
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.OPENSSH;
  }

  /** Construct matcher object. */
  public OpenSSH() {
    pattRe = Pattern.compile(matchRe);
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public OpenSSH(String input, Event e, ParserState state) {
    pattAuthAcceptedRe = Pattern.compile(authAcceptedRe);
    Matcher mat = pattAuthAcceptedRe.matcher(input);
    if (mat.matches()) {
      String authTimestamp = mat.group(1);
      hostname = mat.group(2);
      authMethod = mat.group(3);
      user = mat.group(4);
      setSourceAddress(mat.group(5), state, e.getNormalized());
      Normalized n = e.getNormalized();
      n.addType(Normalized.Type.AUTH);
      n.setSubjectUser(user);
      n.setObject(hostname);

      DateTime et = Parser.parseAndCorrectSyslogTs(authTimestamp, e);
      if (et != null) {
        e.setTimestamp(et);
      }

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
  }

  /**
   * Get username
   *
   * @return Username
   */
  public String getUser() {
    return user;
  }

  /**
   * Get authentication method
   *
   * @return Authentication method
   */
  public String getAuthMethod() {
    return authMethod;
  }

  @Override
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    switch (property) {
      case OPENSSH_AUTHMETHOD:
        return getAuthMethod();
    }
    return null;
  }
}
