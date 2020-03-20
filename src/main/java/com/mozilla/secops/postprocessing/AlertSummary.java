package com.mozilla.secops.postprocessing;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.beam.sdk.coders.AvroCoder;
import org.apache.beam.sdk.coders.DefaultCoder;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Combine.CombineFn;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.SlidingWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Summarize alerts and various attributes of alerts over time and generate subsequent alerts if
 * certain thresholds or anomolies are detected.
 *
 * <p>This transform requires configuration be passed in using {@link
 * PostProcessing.PostProcessingOptions}.
 *
 * <p>The format of each threshold should be classifier:percentup:precentdown:minimum. A percent
 * up/down value of 0 will effectively disable that type of check.
 *
 * <p>The classifier "*" will apply the thresholding to all alerts. For example, *:10:10:100 will
 * generate an alert if a 10% increase or decrease in alerts was seen with a minimum of 100 in the
 * newest window being considered.
 *
 * <p>To apply the threshold for all alerts associated with a given monitored resource, the resource
 * name can be used. For example www.mozilla.org:50:0:10 will generate an alert if a 50% increase is
 * seen with at least 10 alerts in the latest window, but will not generate an alert on decrease.
 *
 * <p>To further apply the threshold to a specific resource and a specific alert category, append
 * the category to the resource name. For example www.mozilla.org-httprequest:50:0:10. This can be
 * further extended with the subcategory, example www.mozilla.org-httprequest-error_rate:50:0:10.
 *
 * <p>Currently thresholds are evaluated on adjacent 15 minute windows, and adjacent 1 hour windows.
 *
 * <p>In some locations in the code there are references to "sblock" and "lblock". This corresponds
 * to the smallest resolution we use for summary, and the largest window we will summarize alerts
 * over.
 */
public class AlertSummary extends PTransform<PCollection<Alert>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private static final int WINDOW_RESOLUTION_MINS_SBLOCK = 15;
  private static final String CLASSIFIER_GLOBAL_STRING = "*";
  private static final String CLASSIFIER_SEPARATOR = "-";

  private final String[] thresholds;
  private final String warningEmail;

  private Logger log;

  public String getTransformDoc() {
    return String.format(
        "Analyze alerts across windows to identify threshold violations"
            + " and anomalies. Applied criteria, [%s].",
        String.join(",", thresholds));
  }

  /**
   * Initialize new {@link AlertSummary}
   *
   * @param options Pipeline options
   */
  public AlertSummary(PostProcessing.PostProcessingOptions options) {
    log = LoggerFactory.getLogger(AlertSummary.class);

    thresholds = options.getAlertSummaryAnalysisThresholds();
    warningEmail = options.getWarningSeverityEmail();

    if (thresholds == null) {
      throw new IllegalArgumentException("no thresholds specified");
    }

    for (int i = 0; i < thresholds.length; i++) {
      String[] parts = thresholds[i].split(":");
      if (parts.length != 4) {
        throw new IllegalArgumentException("threshold had invalid format");
      }
      int x, y, z = 0;
      try {
        x = Integer.parseInt(parts[1]);
        y = Integer.parseInt(parts[2]);
        z = Integer.parseInt(parts[3]);
      } catch (NumberFormatException exc) {
        throw new IllegalArgumentException("invalid integer in threshold");
      }
      if (x < 0 || y < 0 || z < 0) {
        throw new IllegalArgumentException("threshold value cannot be negative");
      }
      log.info("adding threshold {}", thresholds[i]);
    }

    if (warningEmail == null) {
      log.warn("no escalation emailed specified, notification disabled");
    } else {
      log.info("notification set to {}", warningEmail);
    }
  }

  private static class AlertSummaryCombineFn
      extends CombineFn<KV<Instant, Alert>, PaneSummary, PaneSummary> {
    private static final long serialVersionUID = 1L;

    @Override
    public PaneSummary createAccumulator() {
      return new PaneSummary();
    }

    @Override
    public PaneSummary addInput(PaneSummary col, KV<Instant, Alert> input) {
      if (col.getTimestamp() == null) {
        col.setTimestamp(input.getKey());
      }
      col.processClassifiers(input.getValue());
      return col;
    }

    @Override
    public PaneSummary mergeAccumulators(Iterable<PaneSummary> cols) {
      PaneSummary ret = new PaneSummary();
      for (PaneSummary i : cols) {
        if (ret.getTimestamp() == null) {
          ret.setTimestamp(i.getTimestamp());
        }
        ret.merge(i);
      }
      return ret;
    }

    @Override
    public PaneSummary extractOutput(PaneSummary col) {
      return col;
    }

    @Override
    public PaneSummary defaultValue() {
      return new PaneSummary();
    }
  }

  @DefaultCoder(AvroCoder.class)
  private static class PaneSummary implements Serializable {
    private static final long serialVersionUID = 1L;

    private HashMap<String, Integer> counters = new HashMap<>();
    private Instant timestamp;

    public void setTimestamp(Instant timestamp) {
      this.timestamp = timestamp;
    }

    public Instant getTimestamp() {
      return timestamp;
    }

    public HashMap<String, Integer> getCounters() {
      return counters;
    }

    public void merge(PaneSummary inbound) {
      // If the pane summary we are merging in has a later timestamp then what we have,
      // use the later timestamp.
      if (inbound.getTimestamp() != null) {
        if (timestamp == null || inbound.getTimestamp().isAfter(timestamp)) {
          timestamp = inbound.getTimestamp();
        }
      }
      for (Map.Entry<String, Integer> entry : inbound.getCounters().entrySet()) {
        int c = counters.containsKey(entry.getKey()) ? counters.get(entry.getKey()) : 0;
        counters.put(entry.getKey(), c + entry.getValue());
      }
    }

    public boolean isEmpty() {
      // Use the global classifier string to see if we have processed data
      return counters.get(CLASSIFIER_GLOBAL_STRING) == null;
    }

    public void processClassifiers(Alert a) {
      ArrayList<String> classifiers = classifierCounters(a);
      for (String i : classifiers) {
        int c = counters.containsKey(i) ? counters.get(i) : 0;
        counters.put(i, c + 1);
      }
    }

    public ArrayList<String> classifierCounters(Alert a) {
      // Given an input alert, we want to return a list of classifier strings that should
      // match on the alert.
      ArrayList<String> ret = new ArrayList<>();
      ret.add(CLASSIFIER_GLOBAL_STRING); // e.g., *
      String mr = a.getMetadataValue("monitored_resource");
      if (mr != null) {
        ret.add(mr); // e.g., www.mozilla.org
      } else {
        return ret;
      }
      String cat = a.getCategory();
      if (cat != null) {
        ret.add(cat); // e.g., httprequest
        ret.add(mr + CLASSIFIER_SEPARATOR + cat); // e.g., www.mozilla.org-httprequest

        String sc = a.getSubcategory();
        if (sc != null) {
          ret.add(
              mr
                  + CLASSIFIER_SEPARATOR
                  + cat
                  + CLASSIFIER_SEPARATOR
                  + sc); // e.g., www.mozilla.org-httprequest-threshold_analysis
        }
      }
      return ret;
    }

    PaneSummary() {
      timestamp = null;
      counters = new HashMap<String, Integer>();
    }
  }

  private static class Evaluator extends DoFn<KV<Boolean, Iterable<PaneSummary>>, Alert> {
    private static final long serialVersionUID = 1L;

    private final String[] thresholds;
    private final String warningEmail;
    private final long width;

    private Logger log;

    Evaluator(String[] thresholds, String warningEmail, long width) {
      log = LoggerFactory.getLogger(AlertSummary.class);
      this.thresholds = thresholds;
      this.warningEmail = warningEmail;
      this.width = width;
    }

    private Alert createAlert(
        String threshold, int ov, int nv, Instant widthStart, Instant maxTimestamp) {
      String timeframe = null;
      if ((maxTimestamp.getMillis() - widthStart.getMillis() + 1) > 1800000) {
        timeframe = "1h";
      } else {
        timeframe = "15m";
      }
      Alert ret = new Alert();
      ret.setCategory("postprocessing");
      ret.setSubcategory("alertsummary");
      ret.setSummary(
          String.format(
              "alert %s, %d alerts -> %d alerts over previous %s using criteria %s",
              ov < nv ? "increase" : "decrease", ov, nv, timeframe, threshold));
      ret.addMetadata("threshold", threshold);
      ret.addMetadata("start", widthStart.toString());
      ret.addMetadata("end", maxTimestamp.toString());
      if (warningEmail != null) {
        ret.addMetadata("notify_email_direct", warningEmail);
      }
      return ret;
    }

    private ArrayList<Alert> executeEvaluation(
        PaneSummary o, PaneSummary n, Instant widthStart, Instant maxTimestamp) {
      ArrayList<Alert> ret = new ArrayList<>();

      for (int i = 0; i < thresholds.length; i++) {
        // We make an assumption here thresholds has been validated for correct format
        String[] criteria = thresholds[i].split(":");

        String classifier = criteria[0];
        // This criteria needs to exist in both the old and new PaneSummary, if not we will not
        // assess it
        if (!o.getCounters().containsKey(classifier) || !n.getCounters().containsKey(classifier)) {
          continue;
        }
        int oldvalue = o.getCounters().get(classifier);
        int newvalue = n.getCounters().get(classifier);

        int pi = Integer.parseInt(criteria[1]);
        int pd = Integer.parseInt(criteria[2]);
        int min = Integer.parseInt(criteria[3]);

        if (newvalue < min) {
          continue;
        }

        double increase = (double) (newvalue - oldvalue) / oldvalue * 100.00;
        double decrease = (double) (oldvalue - newvalue) / oldvalue * 100.00;

        if (pi != 0 && (int) increase > pi) {
          ret.add(createAlert(thresholds[i], oldvalue, newvalue, widthStart, maxTimestamp));
        }
        if (pd != 0 && (int) decrease > pd) {
          ret.add(createAlert(thresholds[i], oldvalue, newvalue, widthStart, maxTimestamp));
        }
      }

      return ret;
    }

    @ProcessElement
    public void processElement(ProcessContext c, BoundedWindow w) {
      int cnt = 0;
      Instant maxTimestamp = null;
      // Locate the maximum pane timestamp in the window; we can use this along with the analysis
      // width to calculate the division point between the summaries
      for (PaneSummary i : c.element().getValue()) {
        if (maxTimestamp == null) {
          maxTimestamp = i.getTimestamp();
        } else {
          if (i.getTimestamp().isAfter(maxTimestamp)) {
            maxTimestamp = i.getTimestamp();
          }
        }
        cnt++;
      }
      Instant widthStart = maxTimestamp.minus(width - 1);
      Instant cutoff = widthStart.plus(width / 2);
      PaneSummary o = new PaneSummary();
      PaneSummary n = new PaneSummary();
      // Merge the summaries along the cutoff point
      for (PaneSummary i : c.element().getValue()) {
        if (i.getTimestamp().isBefore(cutoff)) {
          o.merge(i);
        } else {
          n.merge(i);
        }
      }
      if (o.isEmpty() || n.isEmpty()) {
        log.info("{} -> {}, no summarized panes, skipping evaluation", widthStart, maxTimestamp);
        return;
      }
      if (o.isEmpty()) {
        log.info("{} -> {}, missing older summary, skipping evaluation", widthStart, maxTimestamp);
        return;
      }
      log.info("{} -> {} -> {}, evaluating summarized panes", widthStart, cutoff, maxTimestamp);
      for (Alert i : executeEvaluation(o, n, widthStart, maxTimestamp)) {
        c.output(i);
      }
    }
  }

  private PCollection<PaneSummary> createSBlockSummary(PCollection<Alert> col) {
    // Return a PaneSummary based on the smallest window block size we will look at which is
    // WINDOW_RESOLUTION_MINS_SBLOCK. This collection forms the basis for all future comparisons
    // and window summaries we will look at.
    return col.apply(
            "sblock window",
            Window.<Alert>into(
                FixedWindows.of(Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK))))
        .apply(
            "sblock key with window timestamp",
            ParDo.of(
                new DoFn<Alert, KV<Instant, Alert>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c, BoundedWindow w) {
                    // We want to a way to determine which WINDOW_RESOLUTION_MINS_SBLOCK length
                    // window this element was a part of later, even if it is windowed again. Key it
                    // with the timestamp indicating the end of the window so we can incorporate it
                    // into the PaneSummary during combine.
                    //
                    // We could probably also look at using the element timestamp but using the
                    // window timestamp ensures a predictable result.
                    c.output(KV.of(w.maxTimestamp(), c.element()));
                  }
                }))
        .apply("sblock combine", Combine.globally(new AlertSummaryCombineFn()).withoutDefaults());
  }

  @Override
  public PCollection<Alert> expand(PCollection<Alert> col) {
    PCollection<PaneSummary> sBlocks = createSBlockSummary(col);

    return PCollectionList.of(
            sBlocks
                .apply(
                    "sblocks window",
                    Window.<PaneSummary>into(
                        SlidingWindows.of(
                                Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK * 2))
                            .every(Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK))))
                .apply(
                    "sblocks key for singleton",
                    ParDo.of(
                        new DoFn<PaneSummary, KV<Boolean, PaneSummary>>() {
                          private static final long serialVersionUID = 1L;

                          @ProcessElement
                          public void processElement(ProcessContext c) {
                            c.output(KV.of(true, c.element()));
                          }
                        }))
                .apply("sblocks gbk for singleton", GroupByKey.<Boolean, PaneSummary>create())
                .apply(
                    "sblocks evaluate",
                    ParDo.of(
                        new Evaluator(
                            thresholds,
                            warningEmail,
                            Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK * 2)
                                .getMillis())))
                .apply("sblocks rewindow for output", new GlobalTriggers<Alert>(5)))
        .and(
            sBlocks
                .apply(
                    "lblocks window",
                    Window.<PaneSummary>into(
                        SlidingWindows.of(
                                Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK * 8))
                            .every(Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK * 4))))
                .apply(
                    "lblocks key for singleton",
                    ParDo.of(
                        new DoFn<PaneSummary, KV<Boolean, PaneSummary>>() {
                          private static final long serialVersionUID = 1L;

                          @ProcessElement
                          public void processElement(ProcessContext c) {
                            c.output(KV.of(true, c.element()));
                          }
                        }))
                .apply("lblocks gbk for singleton", GroupByKey.<Boolean, PaneSummary>create())
                .apply(
                    "lblocks evaluate",
                    ParDo.of(
                        new Evaluator(
                            thresholds,
                            warningEmail,
                            Duration.standardMinutes(WINDOW_RESOLUTION_MINS_SBLOCK * 8)
                                .getMillis())))
                .apply("lblocks rewindow for output", new GlobalTriggers<Alert>(5)))
        .apply(Flatten.<Alert>pCollections());
  }
}
