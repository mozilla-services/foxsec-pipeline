package com.mozilla.secops.parser.models.cloudtrail;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.HashMap;

/** Model for Cloudtrail Events JSON parsing */
public class CloudtrailEvent implements Serializable {
  private static final long serialVersionUID = 1L;

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

  private UserIdentity userIdentity;

  private HashMap<String, Object> responseElements;
  private HashMap<String, Object> requestParameters;

  public String getAccessKeyID() {
    return accessKeyID;
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
    return userIdentity.getType();
  }

  @JsonProperty("userIdentity")
  public UserIdentity getUserIdentity() {
    return userIdentity;
  }

  @JsonProperty("responseElements")
  public HashMap<String, Object> getResponseElements() {
    return responseElements;
  }

  @JsonProperty("requestParameters")
  public HashMap<String, Object> getRequestParameters() {
    return requestParameters;
  }

  /**
   * Get the identity name depending on the user type
   *
   * @return String Identity Name
   */
  public String getIdentityName() {
    if (getUserType().equals("IAMUser")) {
      return userIdentity.getUserName();
    } else if (getUserType().equals("AssumedRole")) {
      return userIdentity.getSessionIssuerValue("userName");
    } else if (getUserType().equals("AWSService")) {
      return userIdentity.getInvokedBy();
    } else if (getUserType().equals("AWSAccount")) {
      return userIdentity.getAccountId();
    }

    return null;
  }

  public Object getResponseElementsValue(String key) {
    if (responseElements == null) {
      return null;
    }
    return responseElements.get(key);
  }
}
