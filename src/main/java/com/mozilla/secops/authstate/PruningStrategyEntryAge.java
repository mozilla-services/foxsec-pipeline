package com.mozilla.secops.authstate;

import java.util.Iterator;
import java.util.Map;
import org.joda.time.DateTimeUtils;

/**
 * Entry age based pruning
 *
 * <p>Entries in a model are removed according to how old they are.
 */
public class PruningStrategyEntryAge implements PruningStrategy {
  public static final long DEFAULTPRUNEAGE = 864000L; // 10 days

  private long entryAgePruningSeconds = DEFAULTPRUNEAGE;

  /**
   * Set age after which entries will be pruned from the model
   *
   * @param entryAgePruningSeconds Age in seconds after which entry will be pruned
   */
  public void setEntryAgePruningSeconds(long entryAgePruningSeconds) {
    this.entryAgePruningSeconds = entryAgePruningSeconds;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Implementation of method of {@link PruningStrategyEntryAge}
   */
  public void pruneState(AuthStateModel s) {
    Map<String, AuthStateModel.ModelEntry> entries = s.getEntries();

    Iterator<?> it = entries.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<?, ?> p = (Map.Entry) it.next();
      AuthStateModel.ModelEntry me = (AuthStateModel.ModelEntry) p.getValue();
      long mts = me.getTimestamp().getMillis() / 1000;
      if ((DateTimeUtils.currentTimeMillis() / 1000) - mts > entryAgePruningSeconds) {
        it.remove();
      }
    }
  }
}
