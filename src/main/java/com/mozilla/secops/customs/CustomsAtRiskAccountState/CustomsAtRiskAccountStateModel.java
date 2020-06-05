package com.mozilla.secops.customs.CustomsAtRiskAccountState;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.joda.time.DateTime;

public class CustomsAtRiskAccountStateModel {
  private String subject;

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
     * Get ip address of entry
     *
     * @return Ip that did account status check
     */
    @JsonProperty("ipAddress")
    public String getIpAddress() {
      return ipAddress;
    }

    public void setIpAddress(String ip) {
      ipAddress = ip;
    }
  }
}
