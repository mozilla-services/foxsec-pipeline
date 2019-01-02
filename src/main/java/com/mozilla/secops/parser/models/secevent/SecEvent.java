package com.mozilla.secops.parser.models.secevent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import org.joda.time.DateTime;

/** Generic Security Event */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecEvent implements Serializable {
  private static final long serialVersionUID = 1L;

  private String secEventVersion;

  // Fields describing information about the subject that is undertaking a given
  // event
  private String actorAccountId;
  private String action;
  private String sourceAddress;
  private String sourceAddressCity;
  private String sourceAddressCountry;

  private String emailRecipient;
  private String smsRecipient;
  private String destinationAccountId;

  private DateTime timestamp;

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
  public String getSourceAddress() {
    return sourceAddress;
  }

  /**
   * Get source address city
   *
   * @return Source address city
   */
  @JsonProperty("source_address_city")
  public String getSourceAddressCity() {
    return sourceAddressCity;
  }

  /**
   * Set source address city
   *
   * @param value City value
   */
  public void setSourceAddressCity(String value) {
    sourceAddressCity = value;
  }

  /**
   * Get source address country
   *
   * @return Source address country
   */
  @JsonProperty("source_address_country")
  public String getSourceAddressCountry() {
    return sourceAddressCountry;
  }

  /**
   * Set source address country
   *
   * @param value Country value
   */
  public void setSourceAddressCountry(String value) {
    sourceAddressCountry = value;
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
   * Get timestamp
   *
   * @return Timestamp
   */
  @JsonProperty("timestamp")
  public DateTime getTimestamp() {
    return timestamp;
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

  public SecEvent() {}
}
