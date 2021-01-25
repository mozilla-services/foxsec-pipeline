package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.MiscUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.amo.AmoMetrics.HeuristicMetrics;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/**
 * Detect distributed submissions based on file size intervals
 *
 * <p>Operates on fixed windows of 5 minutes. Uploads seen during this window are grouped based on
 * file size rounded up to the nearest 10000 byte boundary. Where the number of uploads at a
 * particular interval exceeds the configured alerting value, an alert will be generated.
 */
public class AddonMultiSubmit extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer suppressRecovery;
  private final int matchAlertOn;
  private final HeuristicMetrics metrics;

  /**
   * Construct new AddonMultiSubmit
   *
   * @param monitoredResource Monitored resource indicator
   * @param suppressRecovery Optional recovery suppression to include with alerts in seconds
   * @param matchAlertOn Number of submissions at rounded interval to trigger alert
   */
  public AddonMultiSubmit(
      String monitoredResource, Integer suppressRecovery, Integer matchAlertOn) {
    this.monitoredResource = monitoredResource;
    this.suppressRecovery = suppressRecovery;
    this.matchAlertOn = matchAlertOn;
    metrics = new HeuristicMetrics(this.getClass().getName());
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return String.format(
        "Detect distributed submissions based on file size intervals. Alert on %s submissions of the same rounded interval.",
        matchAlertOn);
  }

  private static Integer roundSize(Integer input) {
    if ((input % 10000) == 0) {
      return input;
    }
    return (10000 - input % 10000) + input;
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "addon multi submit fixed window",
            Window.<Event>into(FixedWindows.of(Duration.standardMinutes(5))))
        .apply(
            "addon multi submit filter applicable",
            ParDo.of(
                new DoFn<Event, KV<Integer, String>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();
                    if (!e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                      return;
                    }
                    AmoDocker d = e.getPayload();
                    if ((d == null) || (d.getEventType() == null)) {
                      return;
                    }
                    if (!d.getEventType().equals(AmoDocker.EventType.FILEUPLOADMNT)) {
                      return;
                    }
                    metrics.eventTypeMatched();

                    // We want at least an email address and a file size
                    if ((d.getFxaEmail() == null) || (d.getBytes() == null)) {
                      return;
                    }

                    // Ignore anything less than 3000 bytes
                    if (d.getBytes() <= 3000) {
                      return;
                    }

                    c.output(KV.of(roundSize(d.getBytes()), d.getFxaEmail()));
                  }
                }))
        .apply("addon multi submit distinct", Distinct.<KV<Integer, String>>create())
        .apply("addon multi submit gbk", GroupByKey.<Integer, String>create())
        .apply(
            "addon multi submit analysis",
            ParDo.of(
                new DoFn<KV<Integer, Iterable<String>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    ArrayList<String> buf = new ArrayList<>();
                    int cnt = 0;

                    for (String s : c.element().getValue()) {
                      buf.add(s);
                      // When we are building the submission buffer, also include a normalized
                      // version of the address, and a dot normalized version
                      String nb = MiscUtil.normalizeEmailPlus(s);
                      if (!s.equals(nb)) {
                        buf.add(nb);
                      }
                      nb = MiscUtil.normalizeEmailPlusDotStrip(s);
                      if (!s.equals(nb)) {
                        buf.add(nb);
                      }
                      cnt++;
                    }
                    if (cnt < matchAlertOn) {
                      return;
                    }
                    Alert alert = new Alert();
                    alert.setCategory("amo");
                    alert.setSubcategory("amo_abuse_multi_submit");
                    alert.setNotifyMergeKey("amo_abuse_multi_submit");
                    alert.addMetadata(AlertMeta.Key.EMAIL, buf);
                    alert.addMetadata(AlertMeta.Key.COUNT, Integer.toString(cnt));
                    alert.setSummary(
                        String.format(
                            "%s addon abuse multi submit, %d %d",
                            monitoredResource, c.element().getKey(), cnt));
                    if (suppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(suppressRecovery, alert);
                    }
                    c.output(alert);
                  }
                }))
        .apply("addon multi submit global triggers", new GlobalTriggers<Alert>(5));
  }
}
