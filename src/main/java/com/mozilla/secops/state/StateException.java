package com.mozilla.secops.state;

/** Exception indicating a general error in state processing */
public class StateException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Construct new {@link StateException} */
  public StateException(String e) {
    super(e);
  }
}
