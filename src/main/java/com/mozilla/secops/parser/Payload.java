package com.mozilla.secops.parser;

public class Payload<T extends PayloadBase> {
    public enum PayloadType {
        GLB,
        OPENSSH,
        RAW
    }

    private PayloadType type;
    private T data;

    public Payload(T d) {
        data = d;
        type = d.getType();
    }

    public T getData() {
        return data;
    }

    public PayloadType getType() {
        return data.getType();
    }
}
