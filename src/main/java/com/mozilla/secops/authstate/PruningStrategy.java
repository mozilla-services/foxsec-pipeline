package com.mozilla.secops.authstate;

/** A pruning strategy controls how and when entries in a state model are removed from the model. */
public interface PruningStrategy {
  /**
   * Prune model
   *
   * @param s {@link AuthStateModel}
   */
  public void pruneState(AuthStateModel s);
}
