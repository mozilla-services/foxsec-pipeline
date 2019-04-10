package com.mozilla.secops.state;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a generic state interface that can be used to store and load state from or to a
 * persistent storage source
 */
public class State {
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
  }

  /** Flush all keys in the underlying state storage */
  public void deleteAll() throws StateException {
    si.deleteAll();
  }

  /**
   * Perform simple key fetch operation with no intended follow up modification and update of the
   * value. For operations involving a fetch, update, and store a new cursor should be allocated by
   * the caller instead.
   *
   * @param s State key to fetch state for
   * @param cls Class to deserialize state data into
   * @return Returns an object containing state data for key, null if not found
   */
  public <T> T get(String s, Class<T> cls) throws StateException {
    StateCursor c = newCursor();
    try {
      return c.get(s, cls);
    } finally {
      c.commit();
    }
  }

  /**
   * Allocate new state cursor for a set of operations
   *
   * <p>In cases where the underlying {@link StateInterface} supports transactions, allocating a new
   * cursor will begin a new transaction, from which writes will not take effect until the
   * transaction has been commited.
   *
   * <p>If the underlying interface does not support transactions, the new cursor will still provide
   * read and write functionality but it will not provide any form of transaction consistency.
   *
   * @return {@link StateCursor}
   */
  public StateCursor newCursor() {
    return si.newCursor();
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
   * Inidicate state object will no longer be used
   *
   * <p>The done function must be called to ensure any background threads and resources are
   * released.
   */
  public void done() {
    log.info("Closing state interface {}", si.getClass().getName());
    si.done();
  }
}
