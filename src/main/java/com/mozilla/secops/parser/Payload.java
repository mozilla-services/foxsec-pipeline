package com.mozilla.secops.parser;

public class Payload<T extends PayloadBase> {
    public enum PayloadType {
        GLB,
        OPENSSH,
        RAW
    }

    private T data;

    public Payload(T d) {
        data = d;
    }

    public T getData() {
        return data;
    }

    public PayloadType getType() {
        return data.getType();
    }
}
