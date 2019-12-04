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
 * Abuse of FxA password reset endpoints from a single source address
 *
 * <p>Assumed to operate on fixed 10 minute windows.
 */
public class CustomsPasswordResetAbuse
    extends PTransform<PCollection<KV<String, CustomsFeatures>>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer threshold;
  private boolean escalate;

  public String getTransformDocDescription() {
    return String.format(
        "Alert if single source requests password reset for at least %d distinct accounts "
            + "within 10 minute fixed window.",
        threshold);
  }

  /**
   * Initialize new CustomsPasswordResetAbuse
   *
   * @param options Pipeline options
   */
  public CustomsPasswordResetAbuse(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
    threshold = options.getPasswordResetAbuseThreshold();
    escalate = options.getEscalatePasswordResetAbuse();
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, CustomsFeatures>> col) {
    return col.apply(
            "password reset abuse analyze",
            ParDo.of(
                new DoFn<KV<String, CustomsFeatures>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    CustomsFeatures cf = c.element().getValue();

                    if ((cf.getTotalPasswordForgotSendCodeSuccess()
                            + cf.getTotalPasswordForgotSendCodeFailure())
                        < threshold) {
                      return;
                    }

                    String addr = c.element().getKey();
                    ArrayList<Event> events =
                        cf.getEventsOfType(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_SUCCESS);
                    events.addAll(
                        cf.getEventsOfType(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_FAILURE));

                    int cnt = 0;
                    ArrayList<String> seenAcct = new ArrayList<>();
                    for (Event e : events) {
                      String em = CustomsUtil.authGetEmail(e);
                      if (em == null || seenAcct.contains(em)) {
                        continue;
                      }
                      seenAcct.add(em);
                      cnt++;
                    }

                    if (cnt < threshold) {
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
                                + "in 10 minute window",
                            monitoredResource, addr, cnt));
                    c.output(alert);
                  }
                }))
        .apply("password reset abuse global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
