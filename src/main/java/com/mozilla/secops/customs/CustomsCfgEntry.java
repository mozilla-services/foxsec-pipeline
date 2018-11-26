package com.mozilla.secops.customs;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.parser.eventfiltercfg.EventFilterCfg;
import java.io.Serializable;

/** An individual detector configuration within the customs configuration */
public class CustomsCfgEntry implements Serializable {
  private static final long serialVersionUID = 1L;

  private Long slidingWindowLength;
  private Long slidingWindowSlides;
  private Long alertSuppressionLength;
  private Long threshold;
  private EventFilterCfg eventFilterCfg;

  /**
   * Get alert threshold
   *
   * @return Alert threshold
   */
  @JsonProperty("threshold")
  public Long getThreshold() {
    return threshold;
  }

  /**
   * Get sliding window length
   *
   * @return Sliding window length
   */
  @JsonProperty("sliding_window_length")
  public Long getSlidingWindowLength() {
    return slidingWindowLength;
  }

  /**
   * Get sliding window slide interval
   *
   * @return Sliding window slide interval
   */
  @JsonProperty("sliding_window_slides")
  public Long getSlidingWindowSlides() {
    return slidingWindowSlides;
  }

  /**
   * Get alert suppression length
   *
   * @return Alert suppression length
   */
  @JsonProperty("alert_suppression_length")
  public Long getAlertSuppressionLength() {
    return alertSuppressionLength;
  }

  /**
   * Get event filter configuration
   *
   * @return Event filter configuration
   */
  @JsonProperty("filter")
  public EventFilterCfg getEventFilterCfg() {
    return eventFilterCfg;
  }

  public CustomsCfgEntry() {}
}
