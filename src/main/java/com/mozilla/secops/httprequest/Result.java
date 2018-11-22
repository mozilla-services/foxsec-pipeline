package com.mozilla.secops.httprequest;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.mozilla.secops.Violation;
import java.io.IOException;
import java.io.Serializable;
import java.util.UUID;
import org.joda.time.DateTime;

/**
 * A {@link Result} describes a result as returned by analysis functions in the {@link HTTPRequest}
 * pipeline.
 */
public class Result implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Valid {@link Result} types */
  public enum ResultType {
    /** Threshold analysis result */
    @JsonProperty("thresholdanalysis")
    THRESHOLD_ANALYSIS,
    /** Client error rate result */
    @JsonProperty("clienterror")
    CLIENT_ERROR
  }

  private String sourceAddress;
  private DateTime windowTimestamp;
  private UUID resultId;
  private ResultType resultType;

  // Used in THRESHOLD_ANALYSIS results
  private Long count;
  private Double meanValue;
  private Double thresholdModifier;

  // Used in CLIENT_ERROR results
  private Long clientErrorCount;
  private Long maxClientErrorRate;

  /**
   * Constructor for {@link Result}.
   *
   * @param resultType Type of result to create
   */
  public Result(ResultType resultType) {
    resultId = UUID.randomUUID();
    this.resultType = resultType;
  }

  /**
   * Default constructor for {@link Result}
   *
   * <p>Create empty result object
   */
  public Result() {}

  /**
   * Returns unique result ID for this result.
   *
   * @return {@link UUID} associated with result.
   */
  @JsonProperty("id")
  public UUID getResultId() {
    return resultId;
  }

  /**
   * Set id in {@link Result}.
   *
   * @param resultId Result id
   */
  public void setResultId(UUID resultId) {
    this.resultId = resultId;
  }

  /**
   * Get result type
   *
   * @return Type of {@link Result}
   */
  @JsonProperty("type")
  public ResultType getResultType() {
    return resultType;
  }

  /**
   * Set result type
   *
   * @param resultType Type of result
   */
  public void setResultType(ResultType resultType) {
    this.resultType = resultType;
  }

  @Override
  public boolean equals(Object o) {
    Result t = (Result) o;
    return getResultId().equals(t.getResultId());
  }

  @Override
  public int hashCode() {
    return resultId.hashCode();
  }

  /**
   * Set source address value in {@link Result}
   *
   * @param sourceAddress Source address string
   */
  public void setSourceAddress(String sourceAddress) {
    this.sourceAddress = sourceAddress;
  }

  /**
   * Get source address in {@link Result}.
   *
   * @return Source address.
   */
  @JsonProperty("source_address")
  public String getSourceAddress() {
    return sourceAddress;
  }

  /**
   * Set count value in {@link Result}
   *
   * @param count Request count
   */
  public void setCount(Long count) {
    this.count = count;
  }

  /**
   * Get count value in {@link Result}.
   *
   * @return Count value.
   */
  @JsonProperty("count")
  public Long getCount() {
    return count;
  }

  /**
   * Set client error count value in {@link Result}
   *
   * @param clientErrorCount Error count
   */
  public void setClientErrorCount(Long clientErrorCount) {
    this.clientErrorCount = clientErrorCount;
  }

  /**
   * Get client error count value in {@link Result}
   *
   * @return Client error count value.
   */
  @JsonProperty("client_error_count")
  public Long getClientErrorCount() {
    return clientErrorCount;
  }

  /**
   * Set threshold modifier value in {@link Result}.
   *
   * @param thresholdModifier Threshold modifier value.
   */
  public void setThresholdModifier(Double thresholdModifier) {
    this.thresholdModifier = thresholdModifier;
  }

  /**
   * Get threshold modifier value in {@link Result}.
   *
   * @return Threshold modifier value.
   */
  @JsonProperty("threshold_modifier")
  public Double getThresholdModifier() {
    return thresholdModifier;
  }

  /**
   * Set mean value in {@link Result}.
   *
   * @param meanValue Mean request value for analysis window.
   */
  public void setMeanValue(Double meanValue) {
    this.meanValue = meanValue;
  }

  /**
   * Get mean value in {@link Result}.
   *
   * @return Mean request value for analysis window.
   */
  @JsonProperty("mean_value")
  public Double getMeanValue() {
    return meanValue;
  }

  /**
   * Set maximum error rate value in {@link Result}
   *
   * @param maxClientErrorRate Maximum client error rate for result
   */
  public void setMaxClientErrorRate(Long maxClientErrorRate) {
    this.maxClientErrorRate = maxClientErrorRate;
  }

  /**
   * Get maximum error rate for result
   *
   * @return Maximum error rate
   */
  @JsonProperty("max_client_errors")
  public Long getMaxClientErrorRate() {
    return maxClientErrorRate;
  }

  /**
   * Set timestamp associated with analysis window in {@link Result}.
   *
   * @param windowTimestamp Timestamp describing analysis window.
   */
  public void setWindowTimestamp(DateTime windowTimestamp) {
    this.windowTimestamp = windowTimestamp;
  }

  /**
   * Get timestamp associated with analysis window in {@link Result}.
   *
   * @return Timestamp describing analysis window.
   */
  @JsonProperty("window_timestamp")
  public DateTime getWindowTimestamp() {
    return windowTimestamp;
  }

  /**
   * Return JSON string representation.
   *
   * @return String or null if serialization fails.
   */
  public String toJSON() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setSerializationInclusion(Include.NON_NULL);
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException exc) {
      return null;
    }
  }

  /**
   * Return {@link Result} from JSON string
   *
   * @param input Result in JSON
   * @return {@link Result} object or null if deserialization fails.
   */
  public static Result fromJSON(String input) {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    try {
      return mapper.readValue(input, Result.class);
    } catch (IOException exc) {
      return null;
    }
  }

  /**
   * Return {@link Violation} object given {@link Result}
   *
   * <p>This function, given values in the result data set will emit a violation notice applicable
   * to the result type.
   *
   * @return {@link Violation} object, or null if no violation was applicable for result
   */
  public Violation toViolation() {
    if (resultType == ResultType.THRESHOLD_ANALYSIS) {
      return new Violation(
          sourceAddress, Violation.ViolationType.REQUEST_THRESHOLD_VIOLATION.toString());
    } else if (resultType == ResultType.CLIENT_ERROR) {
      return new Violation(
          sourceAddress, Violation.ViolationType.CLIENT_ERROR_RATE_VIOLATION.toString());
    }
    return null;
  }
}
