package com.mozilla.secops.state;

/** Interface for state implementations */
public interface StateInterface {
  /** Notify state implementation no further processing will occur */
  public void done();

  /**
   * Flush all keys in the state implementation
   *
   * @throws StateException StateException
   */
  public void deleteAll() throws StateException;

  /**
   * Perform any setup required to read and write state
   *
   * @throws StateException StateException
   */
  public void initialize() throws StateException;

  /**
   * Allocate new state cursor
   *
   * @return StateCursor
   * @throws StateException StateException
   */
  public StateCursor newCursor() throws StateException;
}
