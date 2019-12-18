package com.mozilla.secops.alert;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** {@link AlertMeta} is metadata associated with an {@link Alert} */
public class AlertMeta implements Serializable {
  private static final long serialVersionUID = 1L;

  private String key;
  private String value;

  /**
   * Get metadata key
   *
   * @return Key string
   */
  @JsonProperty("key")
  public String getKey() {
    return key;
  }

  /**
   * Set metadata value
   *
   * @param value Value to set
   */
  @JsonProperty("value")
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * Get metadata value
   *
   * @return Value string
   */
  public String getValue() {
    return value;
  }

  /**
   * Create new {@link AlertMeta}
   *
   * @param key Metadata key
   * @param value Metadata value
   */
  @JsonCreator
  public AlertMeta(@JsonProperty("key") String key, @JsonProperty("value") String value) {
    this.key = key;
    this.value = value;
  }
}
