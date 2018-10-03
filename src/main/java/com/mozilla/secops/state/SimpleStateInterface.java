package com.mozilla.secops.state;

import java.util.Map;
import java.util.HashMap;

import java.io.IOException;

public class SimpleStateInterface implements StateInterface {
    private Map<String, String> state;

    public void initialize() throws IOException {
        state = new HashMap<String, String>();
    }

    public String getObject(String s) {
        return state.get(s);
    }

    public void saveObject(String s, String v) {
        state.put(s, v);
    }

    public void done() {
    }

    SimpleStateInterface() {
    }
}
