package com.mozilla.secops.whitelistedips;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.joda.time.DateTime;

public class WhitelistedIp {
  private String ip;
  private DateTime expiresAt;
  private String createdBy;

  @JsonProperty("ip")
  public String getIp() {
    return ip;
  }

  @JsonProperty("expires_at")
  public DateTime getExpiresAt() {
    return expiresAt;
  }

  @JsonProperty("created_by")
  public String getCreatedBy() {
    return createdBy;
  }
}
