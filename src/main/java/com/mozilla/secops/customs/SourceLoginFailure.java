package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/**
 * Simple detection of excessive login failures per-source across fixed window
 *
 * <p>Assumed to operate on 10 minute fixed windows.
 */
public class SourceLoginFailure
    extends PTransform<PCollection<KV<String, CustomsFeatures>>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer threshold;
  private final boolean escalate;

  /**
   * Initialize new SourceLoginFailure
   *
   * @param options CustomsOptions
   */
  public SourceLoginFailure(Customs.CustomsOptions options) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    threshold = options.getSourceLoginFailureThreshold();
    escalate = options.getEscalateSourceLoginFailure();
  }

  public String getTransformDocDescription() {
    return String.format(
        "Alert on %d login failures from a single source in a 10 minute window.", threshold);
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, CustomsFeatures>> col) {
    return col.apply(
            "source login failure analysis",
            ParDo.of(
                new DoFn<KV<String, CustomsFeatures>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    CustomsFeatures cf = c.element().getValue();

                    // If the total login failures is less than our threshold we don't need to
                    // continue with the analysis
                    if (cf.getTotalLoginFailureCount() < threshold) {
                      return;
                    }

                    String addr = c.element().getKey();
                    ArrayList<Event> events =
                        cf.getEventsOfType(FxaAuth.EventSummary.LOGIN_FAILURE);

                    int cnt = 0;
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
                            "%s source login failure threshold exceeded, %s %d in 10 minutes",
                            monitoredResource, addr, cnt));
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

  public boolean isExperimental() {
    return !escalate;
  }
}
