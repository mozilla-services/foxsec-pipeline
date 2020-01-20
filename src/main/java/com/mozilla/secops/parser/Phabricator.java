package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

/** Payload parser for Phabricator audit logs */
public class Phabricator extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Normalized object fields will always be set to this value for events parsed using this payload
   * parser
   */
  public final String PHABRICATOR_OBJECT_VALUE = "phabricator";

  private final String matchRe =
      "^\\[([^\\]]+)\\]\t(\\d+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)"
          + "\t(\\d+)\t(\\d+)$";

  private Pattern pattRe;

  private Integer pid;
  private String hostname;
  private String user;
  private String controller;
  private String function;
  private String path;
  private String referer;
  private Integer status;
  private Integer rtime;

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
    return Payload.PayloadType.PHABRICATOR_AUDIT;
  }

  private String extractValue(String input) {
    if ((input == null) || (input.equals("-"))) {
      return null;
    }
    return input;
  }

  /** Construct matcher object. */
  public Phabricator() {
    pattRe = Pattern.compile(matchRe);
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Phabricator(String input, Event e, ParserState state) {
    pattRe = Pattern.compile(matchRe);
    Matcher mat = pattRe.matcher(input);
    if (!mat.matches()) {
      return;
    }

    DateTimeFormatter dtf = DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss Z");
    DateTime et = dtf.parseDateTime(mat.group(1));
    e.setTimestamp(et);

    pid = new Integer(mat.group(2));
    hostname = mat.group(3);

    user = extractValue(mat.group(5));
    controller = extractValue(mat.group(6));
    function = extractValue(mat.group(7));
    path = extractValue(mat.group(8));
    referer = extractValue(mat.group(9));

    status = extractValue(mat.group(10)) != null ? new Integer(mat.group(10)) : null;
    rtime = extractValue(mat.group(11)) != null ? new Integer(mat.group(11)) : null;

    Normalized n = e.getNormalized();
    setSourceAddress(mat.group(4), state, n);
    if (user != null) {
      n.addType(Normalized.Type.AUTH_SESSION);
      n.setSubjectUser(user);
      n.setObject(PHABRICATOR_OBJECT_VALUE);
    }
  }

  /**
   * Get user value
   *
   * @return String
   */
  public String getUser() {
    return user;
  }

  /**
   * Get controller
   *
   * @return String
   */
  public String getController() {
    return controller;
  }

  /**
   * Get function
   *
   * @return String
   */
  public String getFunction() {
    return function;
  }

  /**
   * Get path
   *
   * @return String
   */
  public String getPath() {
    return path;
  }

  /**
   * Get referer
   *
   * @return String
   */
  public String getReferer() {
    return referer;
  }

  /**
   * Get status
   *
   * @return Integer
   */
  public Integer getStatus() {
    return status;
  }
}
