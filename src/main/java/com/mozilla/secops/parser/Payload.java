package com.mozilla.secops.parser;

public abstract class Payload<T extends Payload> {
    public enum PayloadType {
        GLB,
        OPENSSH,
        RAW,
        UNKNOWN
    }

    private T data;
    private PayloadType type;

    public Payload() {
    }

    public Payload(String input) {
        type = PayloadType.UNKNOWN;
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
