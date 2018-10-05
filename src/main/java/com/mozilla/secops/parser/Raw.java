package com.mozilla.secops.parser;

import java.io.Serializable;

public class Raw extends Payload<Raw> implements Serializable {
    private static final long serialVersionUID = 1L;

    private String raw;

    @Override
    public Boolean matcher(String input) {
        return true;
    }

    public Raw() {
    }

    public Raw(String input, Event e) {
        setType(Payload.PayloadType.RAW);
        raw = input;
    }

    public String getRaw() {
        return raw;
    }
}
