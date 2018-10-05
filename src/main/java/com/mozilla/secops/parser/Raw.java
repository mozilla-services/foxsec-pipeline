package com.mozilla.secops.parser;

import java.io.Serializable;

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

    public Raw() {
    }

    public Raw(String input, Event e) {
        raw = input;
    }

    public String getRaw() {
        return raw;
    }
}
