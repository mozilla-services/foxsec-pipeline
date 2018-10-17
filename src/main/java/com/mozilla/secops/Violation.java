package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Represents a violation as would be submitted to iprepd
 *
 * <p>See <a href="https://github.com/mozilla-services/iprepd">iprepd</a>
 */
public class Violation {
    private final String sourceAddress;
    private final String violation;

    /**
     * Valid violation types
     */
    public enum ViolationType {
        /** HTTP request threshold violation */
        REQUEST_THRESHOLD_VIOLATION {
            @Override
            public String toString() {
                return "request_threshold_violation";
            }
        }
    }

    /**
     * Create new {@link Violation}
     *
     * @param sourceAddress Source address as string
     * @param violation ViolationType
     */
    public Violation(String sourceAddress, String violation) {
        this.sourceAddress = sourceAddress;
        this.violation = violation;
    }

    /**
     * Get source address
     *
     * @return Source address string
     */
    @JsonProperty("ip")
    public String getSourceAddress() {
        return sourceAddress;
    }

    /**
     * Get violation type
     *
     * @return Violation type string
     */
    @JsonProperty("violation")
    public String getViolation() {
        return violation;
    }

    /**
     * Convert {@link Violation} to JSON string
     *
     * @return Violation JSON string or null on serialization failure
     */
    public String toJSON() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException exc) {
            return null;
        }
    }
}
