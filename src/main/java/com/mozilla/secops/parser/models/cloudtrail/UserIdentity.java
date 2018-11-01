package com.mozilla.secops.parser.models.cloudtrail;

/**
 * Model for userIdentity element in Cloudtrail Events
 */
public class UserIdentity {
    public String accessKeyId;
    public String accountId;
    public String arn;
    public String invokedBy;
    public String principalId;
    public String type;
    public String userName;
    public SessionContext sessionContext;

    public String getSessionIssuerValue(String key) {
        if (sessionContext == null) {
            return null;
        }
        if (sessionContext.sessionIssuer == null) {
            return null;
        }
        return sessionContext.sessionIssuer.get(key);
    }

    public String getSessionAttributesValue(String key) {
        if (sessionContext == null) {
            return null;
        }
        if (sessionContext.attributes == null) {
            return null;
        }
        return sessionContext.attributes.get(key);
    }
}
