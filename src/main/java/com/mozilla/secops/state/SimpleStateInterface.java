package com.mozilla.secops.state;

import java.util.Map;
import java.util.HashMap;

public class SimpleStateInterface implements StateInterface {
    private Map<String, String> state;

    public String getObject(String s) {
        return state.get(s);
    }

    public void saveObject(String s, String v) {
        state.put(s, v);
    }
    
    public void done() {
    }

    SimpleStateInterface() {
        state = new HashMap<String, String>();
    }
}
