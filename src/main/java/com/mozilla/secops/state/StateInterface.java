package com.mozilla.secops.state;

import java.io.IOException;

public interface StateInterface {
    public String getObject(String s) throws StateException;
    public void saveObject(String s, String v) throws StateException;
    public void done();
    public void initialize() throws StateException;
}
