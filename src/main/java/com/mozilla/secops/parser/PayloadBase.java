package com.mozilla.secops.parser;

public abstract class PayloadBase {
    public PayloadBase() {
    }

    public PayloadBase(String input, Event e) {
    }

    public Boolean matcher(String input) {
        return false;
    }

    public Payload.PayloadType getType() {
        return null;
    }
}
