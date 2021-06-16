package com.mozilla.secops.httprequest.heuristics;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.HTTPRequestToggles;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.IOException;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Transform for analysis of error rates per client within a given window. */
public class ErrorRateAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final Long maxErrorRate;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;

  private Logger log;

  /**
   * Static initializer for {@link ErrorRateAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   */
  public ErrorRateAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject) {
    maxErrorRate = toggles.getMaxClientErrorRate();
    monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    log = LoggerFactory.getLogger(ErrorRateAnalysis.class);
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return String.format(
        "Alert if a single source address generates more than %d 4xx errors in a "
            + "1 minute window.",
        maxErrorRate);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> input) {
    return input
        .apply(
            "isolate client errors",
            ParDo.of(
                new DoFn<Event, String>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Normalized n = c.element().getNormalized();
                    Integer status = n.getRequestStatus();
                    if (status == null) {
                      return;
                    }
                    if (n.getSourceAddress() == null) {
                      return;
                    }
                    if (status >= 400 && status < 500) {
                      c.output(n.getSourceAddress());
                    }
                  }
                }))
        .apply(Count.<String>perElement())
        .apply(
            "per-client error rate analysis",
            ParDo.of(
                new DoFn<KV<String, Long>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c, BoundedWindow w) {
                    if (c.element().getValue() <= maxErrorRate) {
                      return;
                    }
                    Alert a = new Alert();
                    a.setSummary(
                        String.format(
                            "%s httprequest error_rate %s %d",
                            monitoredResource, c.element().getKey(), c.element().getValue()));
                    a.setCategory("httprequest");
                    a.setSubcategory("error_rate");
                    a.addMetadata(AlertMeta.Key.SOURCEADDRESS, c.element().getKey());

                    if (enableIprepdDatastoreExemptions) {
                      try {
                        IprepdIO.addMetadataIfIpIsExempt(
                            c.element().getKey(), a, iprepdDatastoreExemptionsProject);
                      } catch (IOException exc) {
                        log.error("error checking iprepd exemptions: {}", exc.getMessage());
                        return;
                      }
                    }

                    a.addMetadata(AlertMeta.Key.ERROR_COUNT, c.element().getValue().toString());
                    a.addMetadata(AlertMeta.Key.ERROR_THRESHOLD, maxErrorRate.toString());
                    a.setNotifyMergeKey(String.format("%s error_count", monitoredResource));
                    a.addMetadata(
                        AlertMeta.Key.WINDOW_TIMESTAMP,
                        (new DateTime(w.maxTimestamp())).toString());
                    if (!a.hasCorrectFields()) {
                      throw new IllegalArgumentException("alert has invalid field configuration");
                    }
                    c.output(a);
                  }
                }));
  }
}
