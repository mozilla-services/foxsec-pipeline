package com.mozilla.secops.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class State {
    private ObjectMapper mapper;
    private StateInterface si;
    private final Logger log;

    public State(StateInterface in) {
        si = in;

        log = LoggerFactory.getLogger(State.class);

        mapper = new ObjectMapper();
        mapper.registerModule(new JodaModule());
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
            false);
    }

    public void initialize() throws IOException {
        log.info("Initializing new state interface using {}", si.getClass().getName());
        si.initialize();
    }

    public <T> T get(String s, Class<T> cls) throws IOException {
        log.info("Requesting state for {}", s);
        String lv = si.getObject(s);
        if (lv == null) {
            return null;
        }
        return mapper.readValue(lv, cls);
    }

    public void set(String s, Object o) throws IOException {
        log.info("Writing state for {}", s);
        si.saveObject(s, mapper.writeValueAsString(o));
    }

    public void done() {
        log.info("Closing state interface {}", si.getClass().getName());
        si.done();
    }
}
