package com.mozilla.secops.parser;

public abstract class Payload<T extends Payload<T>> {
    public enum PayloadType {
        GLB,
        OPENSSH,
        RAW
    }

    private PayloadType type;

    public Payload() {
    }

    public Payload(String input, Event e) {
    }

    public Boolean matcher(String input) {
        return false;
    }

    public PayloadType getType() {
        return type;
    }

    protected void setType(PayloadType t) {
        type = t;
    }
}
