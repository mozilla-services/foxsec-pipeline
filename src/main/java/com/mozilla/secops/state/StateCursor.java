package com.mozilla.secops.state;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.IOException;
import java.lang.reflect.Array;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Generic state cursor implementation */
public abstract class StateCursor {
  private final Logger log;
  private final ObjectMapper mapper;

  /**
   * Low level state object fetch operation
   *
   * <p>Most uses should prefer {@link #get}.
   *
   * @param s Key
   * @return Value
   */
  public abstract String getObject(String s) throws StateException;

  /**
   * Low level state object fetch all operation
   *
   * <p>Most uses should prefer {@link #getAll}.
   */
  public abstract String[] getAllObjects() throws StateException;

  /**
   * Low level state object save operation
   *
   * <p>Most uses should prefer {@link #set}.
   *
   * @param s Key
   * @param v Value
   */
  public abstract void saveObject(String s, String v) throws StateException;

  /**
   * Commit transaction
   *
   * <p>For cursors that have an underlying interface implementation that does not support
   * transactions, commit is a noop.
   */
  public abstract void commit() throws StateException;

  private static Boolean validKey(String k) {
    if (k.isEmpty()) {
      return false;
    }
    return true;
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
    String lv = getObject(s);
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
   * Get all state values of the specified kind (specific to Datastore)
   *
   * @param cls Class to deserialize state data into
   * @return Returns an array containing the state data for all keys of the kind in {@link
   *     DatastoreStateInterface}, null if none are found.
   */
  public <T> T[] getAll(Class<T> cls) throws StateException {
    String[] lv = getAllObjects();
    if (lv == null) {
      return null;
    }

    try {
      @SuppressWarnings("unchecked")
      T[] results = (T[]) Array.newInstance(cls, lv.length);
      for (int i = 0; i < lv.length; i++) {
        results[i] = mapper.readValue(lv[i], cls);
      }
      return results;
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
      saveObject(s, mapper.writeValueAsString(o));
    } catch (JsonProcessingException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  /** Allocate new {@link StateCursor} */
  public StateCursor() {
    log = LoggerFactory.getLogger(StateCursor.class);

    mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
  }
}
