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

  /**
   * Flush all keys in the underlying state storage
   *
   * @throws StateException StateException
   */
  public void deleteAll() throws StateException {
    si.deleteAll();
  }

  /**
   * Allocate new state cursor for a set of operations
   *
   * <p>If the transaction flag is true, the new cursor will be allocated as a transaction. In this
   * case be sure to properly commit the transaction in the cursor when complete.
   *
   * @param <T> Class used in state storage
   * @param stateClass Class used in stage storage
   * @param transaction If true, allocate cursor as a transaction
   * @return {@link StateCursor}
   * @throws StateException StateException
   */
  public <T> StateCursor<T> newCursor(Class<T> stateClass, boolean transaction)
      throws StateException {
    return si.newCursor(stateClass, transaction);
  }

  /**
   * Initialize state instance
   *
   * <p>The initialize function should be called prior to reading or writing any state using the
   * {@link State} object.
   *
   * @throws StateException StateException
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
