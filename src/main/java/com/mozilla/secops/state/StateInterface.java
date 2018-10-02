package com.mozilla.secops.state;

public interface StateInterface {
    public String getObject(String s);
    public void saveObject(String s, String v);
    public void done();
}
