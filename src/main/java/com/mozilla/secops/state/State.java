package com.mozilla.secops.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;

import java.io.IOException;

public class State {
    private ObjectMapper mapper;
    private StateInterface si;

    public State(StateInterface in) {
        si = in;

        mapper = new ObjectMapper();
        mapper.registerModule(new JodaModule());
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
            false);
    }

    public void initialize() throws IOException {
        si.initialize();
    }

    public <T> T get(String s, Class<T> cls) throws IOException {
        String lv = si.getObject(s);
        if (lv == null) {
            return null;
        }
        return mapper.readValue(lv, cls);
    }

    public void set(String s, Object o) throws IOException {
        si.saveObject(s, mapper.writeValueAsString(o));
    }

    public void done() {
        si.done();
    }
}
