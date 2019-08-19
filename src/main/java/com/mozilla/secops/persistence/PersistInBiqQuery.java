package com.mozilla.secops.persistence;

import com.google.api.services.bigquery.model.TableRow;
import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.io.gcp.bigquery.BigQueryIO;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/** Composite transform to persist a {@link PCollection} containing {@link Event} objects */
public class PersistInBiqQuery extends PTransform<PCollection<Event>, PDone>
    implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String persistenceBQ;

  /**
   * Initialize new {@link PersistInBiqQuery} transform
   *
   * @param bigQuerySpec the bigquery specification where to persist events
   */
  public PersistInBiqQuery(String bigQuerySpec) {
    persistenceBQ = bigQuerySpec;
  }

  private TableRow buildTableRow(Event e) {
    TableRow r = new TableRow();
    r.set("event_id", e.getEventId());
    r.set("event_type", e.getPayloadType().name());
    r.set("event_time", e.getTimestamp());
    r.set("raw", e.getPayload().toString());
    return r;
  }

  @Override
  public PDone expand(PCollection<Event> events) {
    if (persistenceBQ != null) {
      events
          .apply(
              ParDo.of(
                  new DoFn<Event, TableRow>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();
                      if (e == null) {
                        return;
                      }
                      TableRow r = buildTableRow(e);
                      c.output(r);
                    }
                  }))
          .apply(
              BigQueryIO.writeTableRows()
                  .to(persistenceBQ)
                  .withCreateDisposition(BigQueryIO.Write.CreateDisposition.CREATE_NEVER)
                  .withWriteDisposition(BigQueryIO.Write.WriteDisposition.WRITE_APPEND));
    }
    return PDone.in(events.getPipeline());
  }
}
