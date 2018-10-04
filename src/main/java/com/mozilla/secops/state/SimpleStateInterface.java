package com.mozilla.secops.state;

import java.util.Map;
import java.util.HashMap;

public class SimpleStateInterface implements StateInterface {
    private Map<String, String> state;

    public void initialize() throws StateException {
        state = new HashMap<String, String>();
    }

    public String getObject(String s) throws StateException {
        return state.get(s);
    }

    public void saveObject(String s, String v) throws StateException {
        state.put(s, v);
    }

    public void done() {
    }

    SimpleStateInterface() {
    }
}
