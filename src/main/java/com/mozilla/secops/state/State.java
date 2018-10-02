package com.mozilla.secops.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.datatype.joda.JodaModule;

import java.io.IOException;

public class State {
    private StateInterface si;

    public State(StateInterface in) {
        si = in;
    }

    public <T> T get(String s, Class<T> cls) throws IOException {
        String lv = si.getObject(s);
        if (lv == null) {
            return null;
        }
        ObjectMapper om = new ObjectMapper();
        om.registerModule(new JodaModule());
        om.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                false);
        return om.readValue(lv, cls);
    }

    public void set(String s, Object o) throws IOException {
        ObjectMapper om = new ObjectMapper();
        om.registerModule(new JodaModule());
        om.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                false);
        si.saveObject(s, om.writeValueAsString(o));
    }

    public void done() {
        si.done();
    }
}
