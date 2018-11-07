package com.mozilla.secops.parser.models.secevent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

/**
 * Generic Security Event
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecEvent implements Serializable {
    private static final long serialVersionUID = 1L;

    private String secEventVersion;

    // Fields describing information about the subject that is undertaking a given
    // event
    private String actorAccountId;
    private String action;
    private String sourceAddress;

    private String emailRecipient;
    private String smsRecipient;
    private String destinationAccountId;

    /**
     * Get SecEvent version string
     *
     * @return Version string
     */
    @JsonProperty("secevent_version")
    public String getSecEventVersion() {
        return secEventVersion;
    }

    /**
     * Get actor account ID
     *
     * @return Actor account ID
     */
    @JsonProperty("account_id")
    public String getActorAccountId() {
        return actorAccountId;
    }

    /**
     * Get action
     *
     * @return Action
     */
    @JsonProperty("action")
    public String getAction() {
        return action;
    }

    /**
     * Get source address
     *
     * @return Source address
     */
    @JsonProperty("source_address")
    public String getSourceAddress()  {
        return sourceAddress;
    }

    /**
     * Get email recipient
     *
     * @return Email recipient
     */
    @JsonProperty("email_recipient")
    public String getEmailRecipient() {
        return emailRecipient;
    }

    /**
     * Get SMS recipient
     *
     * @return SMS recipient
     */
    @JsonProperty("sms_recipient")
    public String getSmsRecipient() {
        return smsRecipient;
    }

    /**
     * Get destination account ID
     *
     * @return Destination account ID
     */
    @JsonProperty("destination_account_id")
    public String getDestinationAccountId() {
        return destinationAccountId;
    }

    public SecEvent() {
    }
}
