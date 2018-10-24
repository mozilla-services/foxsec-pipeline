package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

/**
 * {@link AlertMeta} is metadata associated with an {@link Alert}
 */
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
     * Get metadata value
     *
     * @return Value string
     */
    @JsonProperty("value")
    public String getValue() {
        return value;
    }

    /**
     * Create new {@link AlertMeta}
     *
     * @param key Metadata key
     * @param value Metadata value
     */
    public AlertMeta(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
