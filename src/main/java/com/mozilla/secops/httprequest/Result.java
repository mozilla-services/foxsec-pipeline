package com.mozilla.secops.httprequest;

import org.apache.beam.sdk.values.KV;

import org.joda.time.DateTime;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.mozilla.secops.Violation;

import java.util.UUID;
import java.io.Serializable;
import java.io.IOException;

/**
 * A {@link Result} describes a result as returned by analysis functions in
 * the {@link HTTPRequest} pipeline.
 */
public class Result implements Serializable {
    private static final long serialVersionUID = 1L;

    private String sourceAddress;
    private Long count;

    private Double meanValue;
    private Double thresholdModifier;
    private DateTime windowTimestamp;

    private UUID resultId;

    /**
     * Constructor for {@link Result}.
     *
     * @param sourceAddress Source address associated with result.
     * @param count Count of requests for sourceAddress within window.
     */
    public Result(String sourceAddress, Long count) {
        this.sourceAddress = sourceAddress;
        this.count = count;

        resultId = UUID.randomUUID();
    }

    /**
     * Default constructor for {@link Result}
     *
     * <p>Create empty result object
     */
    public Result() {
    }

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

    @Override
    public boolean equals(Object o) {
        Result t = (Result)o;
        return getResultId().equals(t.getResultId());
    }

    @Override
    public int hashCode() {
        return resultId.hashCode();
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
     * Get count value in {@link Result}.
     *
     * @return Count value.
     */
    @JsonProperty("count")
    public Long getCount() {
        return count;
    }

    /**
     * Return a new {@link Result} based on a {@link KV}, where the key is used
     * as the sourceAddress and the value is used as the count.
     *
     * @param element KV element.
     * @return {@link Result} constructed from KV.
     */
    public static Result fromKV(KV<String, Long> element) {
        return new Result(element.getKey(), element.getValue());
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
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                false);
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
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                false);
        try {
            return mapper.readValue(input, Result.class);
        } catch (IOException exc) {
            System.out.println(exc);
            return null;
        }
    }

    /**
     * Return {@link Violation} object given {@link Result}
     *
     * <p>This function, given values in the result data set will emit a violation notice
     * applicable to the result type.
     *
     * @return {@link Violation} object, or null if no violation was applicable for result
     */
    public Violation toViolation() {
        if (count > (thresholdModifier * meanValue)) {
            return new Violation(sourceAddress,
                Violation.ViolationType.REQUEST_THRESHOLD_VIOLATION.toString());
        }
        return null;
    }
}
