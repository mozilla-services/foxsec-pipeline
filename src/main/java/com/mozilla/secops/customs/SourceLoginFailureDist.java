package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.MiscUtil;
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

/**
 * Detect login failures for a single account occuring from multiple source addresses in a fixed
 * window of time.
 */
public class SourceLoginFailureDist extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private static final int windowSizeSeconds = 600;

  private final String monitoredResource;
  private final Integer threshold;

  /**
   * Initialize new SourceLoginFailureDist
   *
   * @param options CustomsOptions
   */
  public SourceLoginFailureDist(Customs.CustomsOptions options) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    threshold = options.getSourceLoginFailureDistributedThreshold();
  }

  public String getTransformDoc() {
    return String.format(
        "Alert on login failures for a particular account from %d different source addresses "
            + "in a %d second fixed window.",
        threshold, windowSizeSeconds);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "source login failure dist key for email",
            ParDo.of(
                new DoFn<Event, KV<String, Event>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();
                    FxaAuth.EventSummary s = CustomsUtil.authGetEventSummary(e);
                    if ((s == null) || (!s.equals(FxaAuth.EventSummary.LOGIN_FAILURE))) {
                      return;
                    }
                    c.output(KV.of(CustomsUtil.authGetEmail(c.element()), e));
                  }
                }))
        .apply(
            "source login failure dist fixed windows",
            Window.<KV<String, Event>>into(
                FixedWindows.of(Duration.standardSeconds(windowSizeSeconds))))
        .apply("source login failure dist gbk", GroupByKey.<String, Event>create())
        .apply(
            "source login failure dist analysis",
            ParDo.of(
                new DoFn<KV<String, Iterable<Event>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    int cnt = 0;

                    String email = c.element().getKey();
                    Iterable<Event> events = c.element().getValue();
                    ArrayList<String> source = new ArrayList<>();

                    for (Event i : events) {
                      String a = CustomsUtil.authGetSourceAddress(i);
                      if (a == null) {
                        continue;
                      }
                      if (!source.contains(a)) {
                        source.add(a);
                        cnt++;
                      }
                    }
                    if (cnt < threshold) {
                      return;
                    }
                    Alert alert = new Alert();
                    alert.setCategory("customs");
                    alert.setTimestamp(Parser.getLatestTimestamp(events));
                    alert.setNotifyMergeKey(Customs.CATEGORY_SOURCE_LOGIN_FAILURE_DIST);
                    alert.addMetadata(
                        "customs_category", Customs.CATEGORY_SOURCE_LOGIN_FAILURE_DIST);
                    // If the email address passes the validator, include it with the alert. If not
                    // we will still generate the alert, but omit including it.
                    if (MiscUtil.validEmail(email)) {
                      alert.addMetadata("email", email);
                    }
                    alert.addMetadata("count", Integer.toString(cnt));
                    alert.setSummary(
                        String.format(
                            "%s distributed source login failure threshold exceeded for single account"
                                + ", %d addresses in %d seconds",
                            monitoredResource, cnt, windowSizeSeconds));
                    String buf = "";
                    for (String s : source) {
                      if (buf.isEmpty()) {
                        buf = s;
                      } else {
                        buf += ", " + s;
                      }
                    }
                    alert.addMetadata("sourceaddresses", buf);
                    c.output(alert);
                  }
                }))
        .apply("source login failure dist global windows", new GlobalTriggers<Alert>(5));
  }
}
