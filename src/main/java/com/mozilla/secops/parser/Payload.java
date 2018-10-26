package com.mozilla.secops.parser;

import java.io.Serializable;

/**
 * Encapsulation for parsed payload data
 */
public class Payload<T extends PayloadBase> implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * Type of payload data stored
     */
    public enum PayloadType {
        /** Google load balancer */
        GLB,
        /** AWS CloudTrail */
        CLOUDTRAIL,
        /** OpenSSH */
        OPENSSH,
        /** Raw */
        RAW
    }

    private T data;

    /**
     * Construct new payload object of specified type
     *
     * @param d Object extending {@link PayloadBase}
     */
    public Payload(T d) {
        data = d;
    }

    /**
     * Get payload data
     *
     * @return Object extending {@link PayloadBase}
     */
    public T getData() {
        return data;
    }

    /**
     * Get payload type
     *
     * @return {@link PayloadType}
     */
    public PayloadType getType() {
        return data.getType();
    }
}
