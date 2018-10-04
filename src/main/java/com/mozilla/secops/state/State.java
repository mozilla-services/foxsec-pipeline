package com.mozilla.secops.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.fasterxml.jackson.core.JsonProcessingException;

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

    private static Boolean validKey(String k) {
        if (k.isEmpty()) {
            return false;
        }
        return true;
    }

    public void initialize() throws StateException {
        log.info("Initializing new state interface using {}", si.getClass().getName());
        si.initialize();
    }

    public <T> T get(String s, Class<T> cls) throws StateException {
        if (!validKey(s)) {
            throw new StateException("invalid key name");
        }
        log.info("Requesting state for {}", s);
        String lv = si.getObject(s);
        if (lv == null) {
            return null;
        }

        try {
            return mapper.readValue(lv, cls);
        } catch (IOException exc) {
            throw new StateException(exc.getMessage());
        }
    }

    public void set(String s, Object o) throws StateException {
        if (!validKey(s)) {
            throw new StateException("invalid key name");
        }
        log.info("Writing state for {}", s);

        try {
            si.saveObject(s, mapper.writeValueAsString(o));
        } catch (JsonProcessingException exc) {
            throw new StateException(exc.getMessage());
        }
    }

    public void done() {
        log.info("Closing state interface {}", si.getClass().getName());
        si.done();
    }
}
