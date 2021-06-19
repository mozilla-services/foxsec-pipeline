package com.mozilla.secops.httprequest.heuristics;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.Stats;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.HTTPRequestMetrics.HeuristicMetrics;
import com.mozilla.secops.httprequest.HTTPRequestToggles;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.IOException;
import java.util.Map;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.Values;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Composite transform that conducts threshold analysis using the configured threshold modifier */
public class ThresholdAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final Double thresholdModifier;
  private final Double requiredMinimumAverage;
  private final Long requiredMinimumClients;
  private final Double clampThresholdMaximum;
  private final Long requiredMinimumRequestsPerClient;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;
  private PCollectionView<Map<String, Boolean>> natView = null;

  private final HeuristicMetrics metrics;
  private Logger log;

  /**
   * Static initializer for {@link ThresholdAnalysis}.
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   * @param natView Use {@link DetectNat} view, or null to disable
   */
  public ThresholdAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject,
      PCollectionView<Map<String, Boolean>> natView) {
    this.thresholdModifier = toggles.getAnalysisThresholdModifier();
    this.requiredMinimumAverage = toggles.getRequiredMinimumAverage();
    this.requiredMinimumClients = toggles.getRequiredMinimumClients();
    this.requiredMinimumRequestsPerClient = toggles.getRequiredMinimumRequestsPerClient();
    this.clampThresholdMaximum = toggles.getClampThresholdMaximum();
    this.monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    this.natView = natView;
    this.metrics = new HeuristicMetrics(ThresholdAnalysis.class.getName());
    log = LoggerFactory.getLogger(ThresholdAnalysis.class);
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return String.format(
        "Alert if a single source address makes more than %.2f times the calculated"
            + " mean request rate for all clients within a 1 minute window.",
        thresholdModifier);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    if (natView == null) {
      // If natView was not set then we just create an empty view for use as the side input
      natView = DetectNat.getEmptyView(col.getPipeline());
    }

    // Count per source address
    PCollection<KV<String, Long>> clientCounts =
        col.apply(
                "calculate per client count",
                ParDo.of(
                    new DoFn<Event, String>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        Normalized n = c.element().getNormalized();
                        if (n.getSourceAddress() == null) {
                          return;
                        }
                        c.output(n.getSourceAddress());
                      }
                    }))
            .apply(Count.<String>perElement());

    // For each client, extract the request count
    PCollection<Long> counts = clientCounts.apply("extract counts", Values.<Long>create());

    // Obtain statistics on the client count population for use as a side input
    final PCollectionView<Stats.StatsOutput> wStats = Stats.getView(counts);

    return clientCounts
        .apply(
            "filter insignificant",
            ParDo.of(
                new DoFn<KV<String, Long>, KV<String, Long>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    if (c.element().getValue() >= requiredMinimumRequestsPerClient) {
                      c.output(c.element());
                    }
                  }
                }))
        .apply(
            "apply thresholds",
            ParDo.of(
                    new DoFn<KV<String, Long>, Alert>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c, BoundedWindow w) {
                        Stats.StatsOutput sOutput = c.sideInput(wStats);
                        Long uc = sOutput.getTotalElements();
                        Map<String, Boolean> nv = c.sideInput(natView);

                        Double cMean = sOutput.getMean();

                        if (uc < requiredMinimumClients) {
                          return;
                        }

                        if (cMean < requiredMinimumAverage) {
                          return;
                        }

                        if ((clampThresholdMaximum != null) && (cMean > clampThresholdMaximum)) {
                          cMean = clampThresholdMaximum;
                        }

                        if (c.element().getValue() >= (cMean * thresholdModifier)) {
                          Boolean isNat = nv.get(c.element().getKey());
                          if (isNat != null && isNat) {
                            log.info(
                                "{}: detectnat: skipping result emission for {}",
                                w.toString(),
                                c.element().getKey());
                            metrics.natDetected();
                            return;
                          }
                          log.info("{}: emitting alert for {}", w.toString(), c.element().getKey());
                          Alert a = new Alert();
                          a.setSummary(
                              String.format(
                                  "%s httprequest threshold_analysis %s %d",
                                  monitoredResource, c.element().getKey(), c.element().getValue()));
                          a.setCategory("httprequest");
                          a.setSubcategory("threshold_analysis");
                          a.addMetadata(AlertMeta.Key.SOURCEADDRESS, c.element().getKey());

                          try {
                            if (enableIprepdDatastoreExemptions) {
                              IprepdIO.addMetadataIfIpIsExempt(
                                  c.element().getKey(), a, iprepdDatastoreExemptionsProject);
                            }
                          } catch (IOException exc) {
                            log.error("error checking iprepd exemptions: {}", exc.getMessage());
                            return;
                          }

                          a.addMetadata(AlertMeta.Key.MEAN, sOutput.getMean().toString());
                          a.addMetadata(AlertMeta.Key.COUNT, c.element().getValue().toString());
                          a.addMetadata(
                              AlertMeta.Key.THRESHOLD_MODIFIER, thresholdModifier.toString());
                          a.setNotifyMergeKey(
                              String.format("%s threshold_analysis", monitoredResource));
                          a.addMetadata(
                              AlertMeta.Key.WINDOW_TIMESTAMP,
                              (new DateTime(w.maxTimestamp())).toString());
                          if (!a.hasCorrectFields()) {
                            throw new IllegalArgumentException(
                                "alert has invalid field configuration");
                          }
                          c.output(a);
                        }
                      }
                    })
                .withSideInputs(wStats, natView));
  }
}
