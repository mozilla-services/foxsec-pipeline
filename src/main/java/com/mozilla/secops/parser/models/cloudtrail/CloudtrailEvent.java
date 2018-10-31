package com.mozilla.secops.parser.models.cloudtrail;

import java.util.HashMap;

public class CloudtrailEvent {
  private String accessKeyID;
  private String awsRegion;
  private String errorCode;
  private String errorMessage;
  private String eventID;
  private String eventName;
  private String eventSource;
  private String eventTime;
  private String eventType;
  private String eventVersion;
  private Boolean readOnly;
  private String recipientAccountID;
  private String requestID;
  private String sourceIPAddress;
  private String userAgent;

  public UserIdentity userIdentity;

  public HashMap<String, Object> responseElements;
  public HashMap<String, Object> requestParameters;

  public String getAccessKeyID() {
    return this.accessKeyID;
  }

  public String getAwsRegion() {
    return awsRegion;
  }

  public String getErrorCode() {
    return errorCode;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

  public String getEventID() {
    return eventID;
  }

  public String getEventName() {
    return eventName;
  }

  public String getEventSource() {
    return eventSource;
  }

  public String getEventTime() {
    return eventTime;
  }

  public String getEventType() {
    return eventType;
  }

  public String getEventVersion() {
    return eventVersion;
  }

  public Boolean getReadOnly() {
    return readOnly;
  }

  public String getRecipientAccountID() {
    return recipientAccountID;
  }

  public String getRequestID() {
    return requestID;
  }

  public String getSourceIPAddress() {
    return sourceIPAddress;
  }

  public String getUserAgent() {
    return userAgent;
  }

  public String getUserType() {
    return userIdentity.type;
  }

  public String getIdentityName() {
    if (getUserType().equals("IAMUser")) {
      return userIdentity.userName;
    } else if (getUserType().equals("AssumedRole")) {
      try {
        String username = userIdentity.sessionContext.sessionIssuer.get("userName");
        return username;
      } catch (NullPointerException exc) {
        return null;
      }
    } else if (getUserType().equals("AWSService")) {
      return userIdentity.invokedBy;
    } else if (getUserType().equals("AWSAccount")) {
      return userIdentity.accountId;
    }

    return null;
  }

  public Boolean wasMFAAuthenticated() {
    try {
      String mfad = userIdentity.sessionContext.attributes.get("mfaAuthenticated");
      return Boolean.parseBoolean(mfad);
    } catch (NullPointerException e) {
      return null;
    }
  }

  public Object getResponseElements(String key) {
    try {
      Object o = responseElements.get(key);
      return o;
    } catch (NullPointerException e) {
      return null;
    }
  }
}
