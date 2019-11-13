package com.mozilla.secops.state;

/** Interface for state implementations */
public interface StateInterface {
  /** Notify state implementation no further processing will occur */
  public void done();

  /** Flush all keys in the state implementation */
  public void deleteAll() throws StateException;

  /** Perform any setup required to read and write state */
  public void initialize() throws StateException;

  /** Allocate new state cursor */
  public StateCursor newCursor() throws StateException;
}
