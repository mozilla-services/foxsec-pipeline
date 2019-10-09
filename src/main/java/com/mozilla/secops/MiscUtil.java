package com.mozilla.secops;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Various miscellaneous utility functions */
public class MiscUtil {
  private static final String emailRe = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

  /**
   * Validate email address format
   *
   * @param input Input
   * @return True if valid, false if not
   */
  public static Boolean validEmail(String input) {
    Pattern p = Pattern.compile(emailRe);
    Matcher m = p.matcher(input);
    if (m.matches()) {
      return true;
    }
    return false;
  }

  /**
   * Normalize an email address, stripping any + component
   *
   * @param input Input string
   * @return Normalized email address
   */
  public static String normalizeEmailPlus(String input) {
    if (input == null) {
      return null;
    }
    int p = input.indexOf('+');
    if (p == -1) {
      return input;
    }
    if (input.charAt(0) == '+') {
      return input;
    }
    int q = input.indexOf('@', p);
    if (q == -1) {
      return input;
    }
    if (input.substring(q).length() == 1) {
      return input;
    }
    return input.substring(0, p) + input.substring(q);
  }

  /**
   * Normalize an email address, stripping + component and any . from user component
   *
   * <p>Should only be utilized in very specific circumstances as not all mail providers handle the
   * . character the same way.
   *
   * @param input Input string
   * @return Normalized email address
   */
  public static String normalizeEmailPlusDotStrip(String input) {
    if (input == null) {
      return null;
    }
    String buf = normalizeEmailPlus(input);
    int p = buf.indexOf('@');
    if (p == -1) {
      return buf;
    }
    String ucom = buf.substring(0, p);
    ucom = ucom.replace(".", "");
    if (ucom.isEmpty()) {
      return buf;
    }
    return ucom + buf.substring(p);
  }
}
