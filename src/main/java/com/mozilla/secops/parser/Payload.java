package com.mozilla.secops.parser;

import java.io.Serializable;

public class Payload<T extends PayloadBase> implements Serializable {
    private static final long serialVersionUID = 1L;

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
