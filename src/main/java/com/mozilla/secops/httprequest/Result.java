package com.mozilla.secops.httprequest;

import org.apache.beam.sdk.values.KV;

import org.joda.time.DateTime;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;
import java.io.Serializable;

/**
 * A {@link Result} describes a result as returned by analysis functions in
 * the {@link HTTPRequest} pipeline.
 */
public class Result implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String sourceAddress;
    private final Long count;

    private Double meanValue;
    private Double thresholdModifier;
    private DateTime windowTimestamp;

    private final UUID resultId;

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
     * Returns unique result ID for this result.
     *
     * @return {@link UUID} associated with result.
     */
    @JsonProperty("id")
    public UUID getResultId() {
        return resultId;
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
}
