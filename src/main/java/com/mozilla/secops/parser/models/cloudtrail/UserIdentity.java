package com.mozilla.secops.parser.models.cloudtrail;

import com.fasterxml.jackson.annotation.JsonSetter;

/**
 * Model for userIdentity element in Cloudtrail Events
 */
public class UserIdentity {
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

    @JsonSetter("sessionContext")
    public void setSessionContext(SessionContext sessionContext) {
        this.sessionContext = sessionContext;
    }
}
