package com.mozilla.secops.authstate;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * All entries are removed from the model with the exception of the entry with the latest timestamp.
 */
public class PruningStrategyLatest implements PruningStrategy {
  /**
   * {@inheritDoc}
   *
   * <p>Implementation of method of {@link PruningStrategyLatest}
   */
  public void pruneState(AuthStateModel s) {
    ArrayList<AbstractMap.SimpleEntry<String, AuthStateModel.ModelEntry>> sorted =
        s.timeSortedEntries();
    int siz = sorted.size();
    if (siz == 0) {
      return;
    }
    HashMap<String, AuthStateModel.ModelEntry> n = new HashMap<>();
    n.put(sorted.get(siz - 1).getKey(), sorted.get(siz - 1).getValue());
    s.setEntries(n);
  }
}
