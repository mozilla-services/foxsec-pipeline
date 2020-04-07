package com.mozilla.secops.parser.models.cloudtrail;

import com.fasterxml.jackson.annotation.JsonSetter;
import java.io.Serializable;

/**
 * Model for userIdentity element in Cloudtrail Events
 *
 * <p>Read about the UserIdentity record here:
 * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
 */
public class UserIdentity implements Serializable {
  private static final long serialVersionUID = 1L;

  private String accessKeyId;
  private String accountId;
  private String arn;
  private String invokedBy;
  private String principalId;
  private String type;
  private String userName;

  private SessionContext sessionContext;

  public String getAccessKeyId() {
    return accessKeyId;
  }

  public String getAccountId() {
    return accountId;
  }

  public String getArn() {
    return arn;
  }

  public String getInvokedBy() {
    return invokedBy;
  }

  public String getPrincipalId() {
    return principalId;
  }

  public String getType() {
    return type;
  }

  public String getUserName() {
    return userName;
  }

  public String getSessionIssuerValue(String key) {
    if (sessionContext == null) {
      return null;
    }
    if (sessionContext.getSessionIssuer() == null) {
      return null;
    }
    return sessionContext.getSessionIssuer().get(key);
  }

  public String getSessionAttributesValue(String key) {
    if (sessionContext == null) {
      return null;
    }
    if (sessionContext.getAttributes() == null) {
      return null;
    }
    return sessionContext.getAttributes().get(key);
  }

  public String getMFAAuthenticated() {
    return getSessionAttributesValue("mfaAuthenticated");
  }

  @JsonSetter("sessionContext")
  public void setSessionContext(SessionContext sessionContext) {
    this.sessionContext = sessionContext;
  }
}
