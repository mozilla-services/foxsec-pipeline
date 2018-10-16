package com.mozilla.secops.parser;

/**
 * Base class for payloads
 */
public abstract class PayloadBase {
    /**
     * Construct matcher object.
     */
    public PayloadBase() {
    }

    /**
     * Construct parser object.
     *
     * @param input Input string.
     * @param e Parent {@link Event}.
     */
    public PayloadBase(String input, Event e) {
    }

    /**
     * Apply matcher.
     *
     * @param input Input string.
     * @return True if matcher matches.
     */
    public Boolean matcher(String input) {
        return false;
    }

    /**
     * Get payload type.
     *
     * @return {@link Payload.PayloadType}
     */
    public Payload.PayloadType getType() {
        return null;
    }
}
