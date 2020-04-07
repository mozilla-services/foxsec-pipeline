package com.mozilla.secops.customs;

import com.mozilla.secops.MiscUtil;
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
 * Detect login failures for a single account occuring from multiple source addresses in a fixed
 * window of time.
 */
public class SourceLoginFailureDist
    extends PTransform<PCollection<KV<String, CustomsFeatures>>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer threshold;
  private final boolean escalate;

  /**
   * Initialize new SourceLoginFailureDist
   *
   * @param options CustomsOptions
   */
  public SourceLoginFailureDist(Customs.CustomsOptions options) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    threshold = options.getSourceLoginFailureDistributedThreshold();
    escalate = options.getEscalateSourceLoginFailureDistributed();
  }

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return String.format(
        "Alert on login failures for a particular account from %d different source addresses "
            + "in a 10 minute fixed window.",
        threshold);
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, CustomsFeatures>> col) {
    return col.apply(
            "source login failure distributed analyze",
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

                    int cnt = 0;

                    String email = c.element().getKey();
                    ArrayList<Event> events =
                        cf.getEventsOfType(FxaAuth.EventSummary.LOGIN_FAILURE);
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
                    alert.setSubcategory(Customs.CATEGORY_SOURCE_LOGIN_FAILURE_DIST);
                    alert.setTimestamp(Parser.getLatestTimestamp(events));
                    alert.setNotifyMergeKey(Customs.CATEGORY_SOURCE_LOGIN_FAILURE_DIST);
                    // If the email address passes the validator, include it with the alert. If not
                    // we will still generate the alert, but omit including it.
                    if (MiscUtil.validEmail(email)) {
                      alert.addMetadata("email", email);
                    }
                    alert.addMetadata("count", Integer.toString(cnt));
                    alert.setSummary(
                        String.format(
                            "%s distributed source login failure threshold exceeded for single account"
                                + ", %d addresses in 10 minutes",
                            monitoredResource, cnt));
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
        .apply("source login failure distributed global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
