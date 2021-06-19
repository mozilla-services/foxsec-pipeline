package com.mozilla.secops.httprequest.heuristics;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
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
import org.apache.beam.sdk.transforms.Filter;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.SerializableFunction;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Transform for analysis of hard per-source request count limit within fixed window */
public class HardLimitAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final Long maxCount;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;
  private PCollectionView<Map<String, Boolean>> natView = null;
  private final HeuristicMetrics metrics;

  private Logger log;

  /**
   * Static initializer for {@link HardLimitAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   * @param natView Use {@link DetectNat} view, or null to disable
   */
  public HardLimitAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject,
      PCollectionView<Map<String, Boolean>> natView) {
    maxCount = toggles.getHardLimitRequestCount();
    monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    this.natView = natView;
    log = LoggerFactory.getLogger(HardLimitAnalysis.class);
    metrics = new HeuristicMetrics(HardLimitAnalysis.class.getName());
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return String.format(
        "Alert if single source address makes more than %d requests in a 1 minute window.",
        maxCount);
  }

  /**
   * Function to be used with filter transform to filter out only ip, count pairs where the count is
   * higher than the hard limit. This is used we only need the side input when an ip address is over
   * the hard limit.
   */
  private class HasCountGreaterThan implements SerializableFunction<KV<String, Long>, Boolean> {
    private static final long serialVersionUID = 1L;

    @Override
    public Boolean apply(KV<String, Long> kv) {
      return kv.getValue() > maxCount;
    }
  }

  @Override
  @SuppressWarnings("deprecation")
  public PCollection<Alert> expand(PCollection<Event> input) {
    if (natView == null) {
      // If natView was not set then we just create an empty view for use as the side input
      natView = DetectNat.getEmptyView(input.getPipeline());
    }
    return input
        .apply(
            "extract client ip",
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
        .apply("hard limit per client count", Count.<String>perElement())
        .apply("filter clients above limit", Filter.by(new HasCountGreaterThan()))
        // Reshuffle to prevent fusion of steps with large input that do not need side input
        // with low volume step that needs side input
        .apply("force materialization of input", org.apache.beam.sdk.transforms.Reshuffle.of())
        .apply(
            "per-source hard limit analysis",
            ParDo.of(
                    new DoFn<KV<String, Long>, Alert>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c, BoundedWindow w) {
                        Map<String, Boolean> nv = c.sideInput(natView);
                        Boolean isNat = nv.get(c.element().getKey());
                        if (isNat != null && isNat) {
                          log.info(
                              "{}: detectnat: skipping result emission for {}",
                              w.toString(),
                              c.element().getKey());
                          metrics.natDetected();
                          return;
                        }
                        Alert a = new Alert();
                        a.setSummary(
                            String.format(
                                "%s httprequest hard_limit %s %d",
                                monitoredResource, c.element().getKey(), c.element().getValue()));
                        a.setCategory("httprequest");
                        a.setSubcategory("hard_limit");
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

                        a.addMetadata(AlertMeta.Key.COUNT, c.element().getValue().toString());
                        a.addMetadata(AlertMeta.Key.REQUEST_THRESHOLD, maxCount.toString());
                        a.setNotifyMergeKey(
                            String.format("%s hard_limit_count", monitoredResource));
                        a.addMetadata(
                            AlertMeta.Key.WINDOW_TIMESTAMP,
                            (new DateTime(w.maxTimestamp())).toString());
                        if (!a.hasCorrectFields()) {
                          throw new IllegalArgumentException(
                              "alert has invalid field configuration");
                        }
                        c.output(a);
                      }
                    })
                .withSideInputs(natView));
  }
}
