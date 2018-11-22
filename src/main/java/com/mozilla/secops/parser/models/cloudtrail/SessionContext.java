package com.mozilla.secops.parser.models.cloudtrail;

import com.fasterxml.jackson.annotation.JsonSetter;
import java.util.HashMap;

/** Model for sessionContext element in Cloudtrail Events */
public class SessionContext {
  private HashMap<String, String> attributes;
  private HashMap<String, String> sessionIssuer;

  public HashMap<String, String> getAttributes() {
    return attributes;
  }

  public HashMap<String, String> getSessionIssuer() {
    return sessionIssuer;
  }

  @JsonSetter("attributes")
  public void setAttributes(HashMap<String, String> attributes) {
    this.attributes = attributes;
  }

  @JsonSetter("sessionIssuer")
  public void setSessionIssuer(HashMap<String, String> sessionIssuer) {
    this.sessionIssuer = sessionIssuer;
  }
}
