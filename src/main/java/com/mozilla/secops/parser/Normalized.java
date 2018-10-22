package com.mozilla.secops.parser;

import java.io.Serializable;

/**
 * Normalized event data
 */
public class Normalized implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * Normalized event types
     */
    public enum Type {
        /** Authentication event */
        AUTH
    }

    private Type type;

    private String subjectUser;
    private String sourceAddress;
    private String object;

    Normalized() {
    }

    /**
     * Get normalized data type
     *
     * @return {@link Normalized.Type}
     */
    public Type getType() {
        return type;
    }

    /**
     * Set normalized data type
     *
     * @param t {@link Normalized.Type}
     */
    public void setType(Type t) {
        type = t;
    }

    /**
     * Set subject user field
     *
     * @param user Username
     */
    public void setSubjectUser(String user) {
        subjectUser = user;
    }

    /**
     * Set source address field
     *
     * @param addr Source address
     */
    public void setSourceAddress(String addr) {
        sourceAddress = addr;
    }

    /**
     * Set object field
     *
     * @param object Object being authenticated to
     */
    public void setObject(String object) {
        this.object = object;
    }

    /**
     * Get subject user field
     *
     * @return Username
     */
    public String getSubjectUser() {
        return subjectUser;
    }

    /**
     * Get source address field
     *
     * @return Source address
     */
    public String getSourceAddress() {
        return sourceAddress;
    }

    /**
     * Get object field
     *
     * @return Object string
     */
    public String getObject() {
        return object;
    }
}
