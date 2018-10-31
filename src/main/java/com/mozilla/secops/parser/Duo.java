package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;

import org.joda.time.DateTime;

import java.io.Serializable;
import java.io.IOException;
import java.util.Map;

/*
 * Payload parser for Duo audit trail log data
 */
public class Duo extends PayloadBase implements Serializable {
    private static final long serialVersionUID = 1L;

    @Override
    public Boolean matcher(String input) {
        return false;
    }

    @Override
    public Payload.PayloadType getType() {
        return Payload.PayloadType.DUO;
    }

    /**
     * Construct matcher object.
     */
    public Duo() {
    }

    /**
     * Construct parser object.
     *
     * @param input Input string.
     * @param e Parent {@link Event}.
     * @param p Parser instance.
     */
    public Duo(String input, Event e, Parser p) {
    }
}
