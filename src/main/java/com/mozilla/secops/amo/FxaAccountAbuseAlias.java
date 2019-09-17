package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.MiscUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Sessions;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/**
 * Analysis for aliased account usage
 *
 * <p>A session gap duration of 120 minutes is used with early firings every 60 seconds. Within the
 * window accounts in use are normalized and grouped together using the normalized value as a key.
 * If the number of in-use aliases for a given account exceeds the configured value, and alert is
 * generated.
 */
public class FxaAccountAbuseAlias extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer suppressRecovery;
  private final int maxAliases;

  /**
   * Create new FxaAccountAbuseAlias
   *
   * @param monitoredResource Monitored resource indicator
   * @param suppressRecovery Optional recovery suppression for abusive accounts
   * @param maxAliases Maximum number of permitted aliases for one account in a given session
   */
  public FxaAccountAbuseAlias(
      String monitoredResource, Integer suppressRecovery, Integer maxAliases) {
    this.monitoredResource = monitoredResource;
    this.suppressRecovery = suppressRecovery;
    this.maxAliases = maxAliases;
  }

  public String getTransformDoc() {
    return String.format(
        "Alerts on aliased FxA accounts usage. A max of %s are allowed for one account in a given session.",
        maxAliases);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "fxa account alias key for sessions",
            ParDo.of(
                new DoFn<Event, KV<String, String>>() {
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
                    if (!d.getEventType().equals(AmoDocker.EventType.GOTPROFILE)) {
                      return;
                    }
                    String ncomp = MiscUtil.normalizeEmailPlus(d.getFxaEmail());
                    if (ncomp == null) {
                      return;
                    }
                    if (ncomp.equals(d.getFxaEmail())) {
                      return;
                    }
                    c.output(KV.of(ncomp, d.getFxaEmail()));
                  }
                }))
        .apply(
            "fxa account alias window for sessions",
            Window.<KV<String, String>>into(Sessions.withGapDuration(Duration.standardMinutes(120)))
                .triggering(
                    Repeatedly.forever(
                        AfterWatermark.pastEndOfWindow()
                            .withEarlyFirings(
                                AfterProcessingTime.pastFirstElementInPane()
                                    .plusDelayOf(Duration.standardSeconds(60)))))
                .withAllowedLateness(Duration.ZERO)
                .accumulatingFiredPanes())
        .apply(GroupByKey.<String, String>create())
        .apply(
            "fxa account alias analysis",
            ParDo.of(
                new DoFn<KV<String, Iterable<String>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    String normalized = c.element().getKey();
                    Iterable<String> alias = c.element().getValue();
                    ArrayList<String> distinct = new ArrayList<>();

                    String metabuf = normalized;
                    for (String s : alias) {
                      if (!distinct.contains(s)) {
                        distinct.add(s);
                        metabuf += ", " + s;
                      }
                    }
                    if (distinct.size() <= maxAliases) {
                      return;
                    }
                    Alert alert = new Alert();
                    alert.setCategory("amo");
                    alert.setNotifyMergeKey("fxa_account_abuse_alias");
                    alert.addMetadata("amo_category", "fxa_account_abuse_alias");
                    alert.addMetadata("email", metabuf);
                    alert.addMetadata("count", Integer.toString(distinct.size()));
                    alert.setSummary(
                        String.format(
                            "%s possible alias abuse in amo, %s has %d aliases",
                            monitoredResource, normalized, distinct.size()));
                    if (suppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(suppressRecovery, alert);
                    }
                    c.output(alert);
                  }
                }))
        .apply("fxa account alias global windows", new GlobalTriggers<Alert>(5));
  }
}
