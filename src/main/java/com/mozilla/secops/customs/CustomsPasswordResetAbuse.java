package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/** Abuse of FxA password reset endpoints */
public class CustomsPasswordResetAbuse extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private static final int windowMinutes = 10;
  private final String monitoredResource;
  private final Integer thresholdPerIp;

  public String getTransformDoc() {
    return String.format(
        "Alert of single source requests password reset for at least %d distinct accounts "
            + "within %d minute fixed window.",
        thresholdPerIp, windowMinutes);
  }

  /**
   * Initialize new CustomsPasswordResetAbuse
   *
   * @param options Pipeline options
   */
  public CustomsPasswordResetAbuse(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
    thresholdPerIp = options.getPasswordResetAbuseWindowThresholdPerIp();
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "password reset abuse filter events",
            ParDo.of(
                new DoFn<Event, KV<String, Event>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    FxaAuth.EventSummary sum = CustomsUtil.authGetEventSummary(e);
                    if (sum == null) {
                      return;
                    }
                    if (!((sum.equals(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_SUCCESS))
                        || (sum.equals(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_FAILURE)))) {
                      return;
                    }

                    if (CustomsUtil.authGetSourceAddress(e) == null) {
                      return;
                    }
                    if (CustomsUtil.authGetEmail(e) == null) {
                      return;
                    }

                    c.output(KV.of(CustomsUtil.authGetSourceAddress(e), e));
                  }
                }))
        .apply(
            "password reset abuse window",
            Window.<KV<String, Event>>into(
                FixedWindows.of(Duration.standardMinutes(windowMinutes))))
        .apply("password reset abuse gbk", GroupByKey.<String, Event>create())
        .apply(
            "password reset abuse analyze",
            ParDo.of(
                new DoFn<KV<String, Iterable<Event>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    String addr = c.element().getKey();
                    Iterable<Event> events = c.element().getValue();

                    int cnt = 0;
                    ArrayList<String> seenAcct = new ArrayList<>();
                    for (Event e : events) {
                      if (seenAcct.contains(CustomsUtil.authGetEmail(e))) {
                        continue;
                      }
                      seenAcct.add(CustomsUtil.authGetEmail(e));
                      cnt++;
                    }

                    if (cnt < thresholdPerIp) {
                      return;
                    }

                    Alert alert = new Alert();
                    alert.setTimestamp(Parser.getLatestTimestamp(events));
                    alert.setCategory("customs");
                    alert.setNotifyMergeKey(Customs.CATEGORY_PASSWORD_RESET_ABUSE);
                    alert.addMetadata("customs_category", Customs.CATEGORY_PASSWORD_RESET_ABUSE);
                    alert.addMetadata("sourceaddress", addr);
                    alert.addMetadata("count", Integer.toString(cnt));
                    alert.setSummary(
                        String.format(
                            "%s %s attempted password reset on %d distinct accounts "
                                + "in %d minute window",
                            monitoredResource, addr, cnt, windowMinutes));
                    c.output(alert);
                  }
                }))
        .apply("password reset global windows", new GlobalTriggers<Alert>(5));
  }
}
