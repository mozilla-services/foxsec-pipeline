package com.mozilla.secops;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.persistence.PersistInBiqQuery;
import java.io.Serializable;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/** {@link CompositePersistence} provides a standardized composite persistence transform */
public class CompositePersistence extends PTransform<PCollection<Event>, PDone>
    implements Serializable {
  private static final long serialVersionUID = 1L;

  private final PersistenceOptions opts;

  /**
   * Initialize new {@link CompositePersistence} transform
   *
   * @param options {@link PersistenceOptions} options
   */
  public CompositePersistence(PersistenceOptions options) {
    opts = options;
  }

  @Override
  public PDone expand(PCollection<Event> events) {
    if (opts.getPersistenceBigQuery() != null) {
      events.apply(new PersistInBiqQuery(opts.getPersistenceBigQuery()));
    }
    return PDone.in(events.getPipeline());
  }
}
