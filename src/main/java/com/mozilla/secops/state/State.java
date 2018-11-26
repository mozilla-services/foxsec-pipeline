package com.mozilla.secops.state;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a generic state interface that can be used to store and load state from or to a
 * persistent storage source
 */
public class State {
  private final ObjectMapper mapper;
  private final StateInterface si;
  private final Logger log;

  /**
   * Construct a new state instance using the specified {@link StateInterface}
   *
   * @param in {@link StateInterface} to use for state storage
   */
  public State(StateInterface in) {
    si = in;

    log = LoggerFactory.getLogger(State.class);

    mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
  }

  private static Boolean validKey(String k) {
    if (k.isEmpty()) {
      return false;
    }
    return true;
  }

  /**
   * Initialize state instance
   *
   * <p>The initialize function should be called prior to reading or writing any state using the
   * {@link State} object.
   */
  public void initialize() throws StateException {
    log.info("Initializing new state interface using {}", si.getClass().getName());
    si.initialize();
  }

  /**
   * Get a state value
   *
   * @param s State key to fetch state for
   * @param cls Class to deserialize state data into
   * @return Returns an object containing state data for key, null if not found
   */
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

  /**
   * Set a state value
   *
   * @param s State key to store state for
   * @param o Object containing state data to serialize into state storage
   */
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

  /** Inidicate state object will no longer be used */
  public void done() {
    log.info("Closing state interface {}", si.getClass().getName());
    si.done();
  }
}
