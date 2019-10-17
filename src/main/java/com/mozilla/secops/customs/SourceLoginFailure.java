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

/**
 * Simple detection of excessive login failures per-source across fixed window
 *
 * <p>The fixed window size is hardcoded to 5 minutes.
 */
public class SourceLoginFailure extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private static final int windowSizeSeconds = 300;

  private final String monitoredResource;
  private final Integer threshold;

  /**
   * Initialize new SourceLoginFailure
   *
   * @param options CustomsOptions
   */
  public SourceLoginFailure(Customs.CustomsOptions options) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    threshold = options.getSourceLoginFailureThreshold();
  }

  public String getTransformDoc() {
    return String.format(
        "Alert on %d login failures from a single source in a %d second window.",
        threshold, windowSizeSeconds);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "source login failure key for source",
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
                    c.output(KV.of(CustomsUtil.authGetSourceAddress(c.element()), e));
                  }
                }))
        .apply(
            "source login failure fixed windows",
            Window.<KV<String, Event>>into(
                FixedWindows.of(Duration.standardSeconds(windowSizeSeconds))))
        .apply("source login failure gbk", GroupByKey.<String, Event>create())
        .apply(
            "source login failure analysis",
            ParDo.of(
                new DoFn<KV<String, Iterable<Event>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    int cnt = 0;

                    String addr = c.element().getKey();
                    Iterable<Event> events = c.element().getValue();
                    ArrayList<String> accts = new ArrayList<>();

                    for (Event i : events) {
                      String a = CustomsUtil.authGetEmail(i);
                      if (a == null) {
                        continue;
                      }
                      if (!accts.contains(a)) {
                        accts.add(a);
                      }
                      cnt++;
                    }
                    if (cnt < threshold) {
                      return;
                    }
                    Alert alert = new Alert();
                    alert.setCategory("customs");
                    alert.setTimestamp(Parser.getLatestTimestamp(events));
                    alert.setNotifyMergeKey(Customs.CATEGORY_SOURCE_LOGIN_FAILURE);
                    alert.addMetadata("customs_category", Customs.CATEGORY_SOURCE_LOGIN_FAILURE);
                    alert.addMetadata("sourceaddress", addr);
                    alert.addMetadata("count", Integer.toString(cnt));
                    alert.setSummary(
                        String.format(
                            "%s source login failure threshold exceeded, %s %d in %d seconds",
                            monitoredResource, addr, cnt, windowSizeSeconds));
                    String buf = "";
                    for (String s : accts) {
                      if (buf.isEmpty()) {
                        buf = s;
                      } else {
                        buf += ", " + s;
                      }
                    }
                    alert.addMetadata("email", buf);
                    c.output(alert);
                  }
                }))
        .apply("source login failure global windows", new GlobalTriggers<Alert>(5));
  }
}
