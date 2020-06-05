package com.mozilla.secops.customs.CustomsAtRiskAccountState;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.joda.time.DateTime;

/** Describes state used by CustomsLoginFailureForAtRiskAccount */
public class CustomsAtRiskAccountStateModel {
  private String subject;

  /** State model entry for at risk account */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ScannedByEntry {
    private DateTime timestamp;
    private String ipAddress;

    /**
     * Get timestamp of entry
     *
     * @return Timestamp as DateTime
     */
    @JsonProperty("timestamp")
    public DateTime getTimestamp() {
      return timestamp;
    }

    /**
     * Set timestamp of entry
     *
     * @param ts Entry timestamp
     */
    public void setTimestamp(DateTime ts) {
      timestamp = ts;
    }

    /**
     * Get IP address of entry
     *
     * @return IP that did account status check
     */
    @JsonProperty("ip_address")
    public String getIpAddress() {
      return ipAddress;
    }

    /**
     * Set IP address of entry
     *
     * @param ip IP address
     */
    public void setIpAddress(String ip) {
      ipAddress = ip;
    }

    /**
     * Create new ScannedByEntry
     *
     * @param ip IP address
     */
    @JsonCreator
    public ScannedByEntry(@JsonProperty("ip_address") String ip) {
      ipAddress = ip;
      timestamp = new DateTime();
    }
  }
}
