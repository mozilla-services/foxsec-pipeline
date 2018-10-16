package com.mozilla.secops.parser;

import java.io.Serializable;

/**
 * Raw payload data
 *
 * <p>If no matcher matches a given input, the resulting event will have a
 * {@link Raw} payload associated with it.
 */
public class Raw extends PayloadBase implements Serializable {
    private static final long serialVersionUID = 1L;

    private String raw;

    @Override
    public Boolean matcher(String input) {
        return true;
    }

    @Override
    public Payload.PayloadType getType() {
        return Payload.PayloadType.RAW;
    }

    /**
     * Construct matcher object.
     */
    public Raw() {
    }

    /**
     * Construct parser object.
     *
     * @param input Input string.
     * @param e Parent {@link Event}.
     */
    public Raw(String input, Event e) {
        raw = input;
    }

    /**
     * Get raw string
     *
     * <p>Returns original event string that could not be parsed.
     *
     * @return Original event string
     */
    public String getRaw() {
        return raw;
    }
}
