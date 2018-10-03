package com.mozilla.secops.state;

import java.io.IOException;

public interface StateInterface {
    public String getObject(String s);
    public void saveObject(String s, String v);
    public void done();
    public void initialize() throws IOException;
}
