package com.mozilla.secops.parser;

import java.io.Serializable;

public class Normalized implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum Type {
        AUTH
    }

    private Type type;

    private String subjectUser;
    private String sourceAddress;

    Normalized() {
    }

    public Type getType() {
        return type;
    }

    public void setType(Type t) {
        type = t;
    }

    public void setSubjectUser(String user) {
        subjectUser = user;
    }

    public void setSourceAddress(String addr) {
        sourceAddress = addr;
    }

    public String getSubjectUser() {
        return subjectUser;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }
}
