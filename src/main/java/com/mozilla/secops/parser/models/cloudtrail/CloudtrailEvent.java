package com.mozilla.secops.parser.models.cloudtrail;

import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.HashMap;

/**
 * Model for Cloudtrail Events JSON parsing
 */
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

    @JsonSetter("userIdentity")
    public void setUserIdentity(UserIdentity userIdentity) {
        this.userIdentity = userIdentity;
    }

    @JsonSetter("responseElements")
    public void setResponseElements(HashMap<String, Object> responseElements) {
        this.responseElements = responseElements;
    }

    @JsonSetter("requestParameters")
    public void setRequestParameters(HashMap<String, Object> requestParameters) {
        this.requestParameters = requestParameters;
    }


    /**
     * Get the identity name depending on the user type
     *
     * @return String Identity Name
     **/
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
