package com.mozilla.secops.alert;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.HashMap;
import java.util.UUID;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

/** Alert format used for notifications to FxA */
public class CustomsAlert implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Severity of a given alert */
  public enum AlertSeverity {
    /** Informational */
    @JsonProperty("info")
    INFORMATIONAL,
    /** Warning */
    @JsonProperty("warn")
    WARNING,
    /** Critical */
    @JsonProperty("critical")
    CRITICAL
  }

  /** Indicator types */
  public enum IndicatorType {
    /** Source IP address */
    @JsonProperty("sourceaddress")
    SOURCEADDRESS,
    /** Account ID/email */
    @JsonProperty("email")
    EMAIL,
    /** Account UID */
    @JsonProperty("uid")
    UID
  }

  /** Alert actions */
  public enum AlertAction {
    /** Consider a report only */
    @JsonProperty("report")
    REPORT,
    /** Indicator should be suspected */
    @JsonProperty("suspect")
    SUSPECT,
    /** Indicator should be blocked temporarily */
    @JsonProperty("block")
    BLOCK,
    /** Indicator should be disabled permanently */
    @JsonProperty("disable")
    DISABLE
  }

  private DateTime timestamp;
  private UUID alertId;
  private IndicatorType indicatorType;
  private String indicator;
  private AlertSeverity severity;
  private Integer confidence;
  private String heuristic;
  private String heuristicDescription;
  private String reason;
  private AlertAction suggestedAction;
  private HashMap<String, Object> details;

  /** Construct new {@link CustomsAlert} */
  public CustomsAlert() {
    alertId = UUID.randomUUID();
    timestamp = new DateTime(DateTimeZone.UTC);
    details = new HashMap<String, Object>();
    severity = AlertSeverity.INFORMATIONAL;
    suggestedAction = AlertAction.REPORT;
  }

  /**
   * Set timestamp
   *
   * @param timestamp DateTime
   */
  @JsonProperty("timestamp")
  public void setTimestamp(DateTime timestamp) {
    this.timestamp = timestamp;
  }

  /**
   * Get timestamp
   *
   * @return DateTime
   */
  public DateTime getTimestamp() {
    return timestamp;
  }

  /**
   * Set UUID
   *
   * @param alertId UUID
   */
  @JsonProperty("id")
  public void setId(UUID alertId) {
    this.alertId = alertId;
  }

  /**
   * Get UUID
   *
   * @return UUID
   */
  public UUID getId() {
    return alertId;
  }

  /**
   * Set indicator type
   *
   * @param indicatorType IndicatorType
   */
  @JsonProperty("indicator_type")
  public void setIndicatorType(IndicatorType indicatorType) {
    this.indicatorType = indicatorType;
  }

  /**
   * Get indicator type
   *
   * @return IndicatorType
   */
  public IndicatorType getIndicatorType() {
    return indicatorType;
  }

  /**
   * Set indicator
   *
   * @param indicator String
   */
  @JsonProperty("indicator")
  public void setIndicator(String indicator) {
    this.indicator = indicator;
  }

  /**
   * Get indicator
   *
   * @return String
   */
  public String getIndicator() {
    return indicator;
  }

  /**
   * Set severity
   *
   * @param severity AlertSeverity
   */
  @JsonProperty("severity")
  public void setSeverity(AlertSeverity severity) {
    this.severity = severity;
  }

  /**
   * Get severity
   *
   * @return AlertSeverity
   */
  public AlertSeverity getSeverity() {
    return severity;
  }

  /**
   * Set confidence
   *
   * @param confidence Integer
   */
  @JsonProperty("confidence")
  public void setConfidence(Integer confidence) {
    this.confidence = confidence;
  }

  /**
   * Get confidence
   *
   * @return Integer
   */
  public Integer getConfidence() {
    return confidence;
  }

  /**
   * Set heuristic
   *
   * @param heuristic String
   */
  @JsonProperty("heuristic")
  public void setHeuristic(String heuristic) {
    this.heuristic = heuristic;
  }

  /**
   * Get heuristic
   *
   * @return String
   */
  public String getHeuristic() {
    return heuristic;
  }

  /**
   * Set heuristic description
   *
   * @param heuristicDescription String
   */
  @JsonProperty("heuristic_description")
  public void setHeuristicDescription(String heuristicDescription) {
    this.heuristicDescription = heuristicDescription;
  }

  /**
   * Get heuristic description
   *
   * @return String
   */
  public String getHeuristicDescription() {
    return heuristicDescription;
  }

  /**
   * Set reason
   *
   * @param reason String
   */
  @JsonProperty("reason")
  public void setReason(String reason) {
    this.reason = reason;
  }

  /**
   * Get reason
   *
   * @return String
   */
  public String getReason() {
    return reason;
  }

  /**
   * Set suggested action
   *
   * @param suggestedAction AlertAction
   */
  @JsonProperty("suggested_action")
  public void setSuggestedAction(AlertAction suggestedAction) {
    this.suggestedAction = suggestedAction;
  }

  /**
   * Get suggested action
   *
   * @return AlertAction
   */
  public AlertAction getSuggestedAction() {
    return suggestedAction;
  }

  /**
   * Set details map
   *
   * @param details HashMap
   */
  @JsonProperty("details")
  public void setDetails(HashMap<String, Object> details) {
    this.details = details;
  }

  /**
   * Get details map
   *
   * @return HashMap
   */
  public HashMap<String, Object> getDetails() {
    return details;
  }
}
