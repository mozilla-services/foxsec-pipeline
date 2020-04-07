package com.mozilla.secops.customs;

import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.customs.Customs.CustomsOptions;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abusive account creation from a single source address
 *
 * <p>Assumed to operate on fixed 10 minute windows.
 */
public class CustomsAccountCreation
    extends PTransform<PCollection<KV<String, CustomsFeatures>>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final int threshold;
  private final String monitoredResource;
  private final Integer accountAbuseSuppressRecovery;
  private final boolean escalate;

  private final Logger log = LoggerFactory.getLogger(CustomsAccountCreation.class);

  /**
   * Create new CustomsAccountCreation
   *
   * @param options Pipeline options
   */
  public CustomsAccountCreation(CustomsOptions options) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    this.threshold = options.getAccountCreationThreshold();
    this.accountAbuseSuppressRecovery = options.getAccountCreationSuppressRecovery();
    this.escalate = options.getEscalateAccountCreation();
  }

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return String.format(
        "Alert if single source address creates %d or more accounts within 10 minute"
            + " fixed window.",
        threshold);
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, CustomsFeatures>> col) {
    return col.apply(
            "account creation analyze",
            ParDo.of(
                new DoFn<KV<String, CustomsFeatures>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    CustomsFeatures cf = c.element().getValue();

                    if (cf.getTotalAccountCreateSuccess() < threshold) {
                      return;
                    }

                    String remoteAddress = c.element().getKey();
                    ArrayList<Event> events =
                        cf.getEventsOfType(FxaAuth.EventSummary.ACCOUNT_CREATE_SUCCESS);

                    int cnt = 0;
                    ArrayList<String> seenAcct = new ArrayList<>();
                    for (Event e : events) {
                      String email = CustomsUtil.authGetEmail(e);
                      if (email == null || seenAcct.contains(email)) {
                        continue;
                      }
                      seenAcct.add(email);
                      cnt++;
                    }

                    if (cnt < threshold) {
                      return;
                    }

                    if (cf.nominalVariance()) {
                      log.info(
                          "{}: skipping notification, variance index {}",
                          remoteAddress,
                          cf.getVarianceIndex());
                      return;
                    }

                    Alert alert = new Alert();
                    alert.setTimestamp(Parser.getLatestTimestamp(events));
                    alert.setCategory("customs");
                    alert.setSubcategory(Customs.CATEGORY_ACCOUNT_CREATION_ABUSE);
                    alert.setNotifyMergeKey(Customs.CATEGORY_ACCOUNT_CREATION_ABUSE);
                    alert.addMetadata("sourceaddress", remoteAddress);
                    alert.addMetadata("count", Integer.toString(cnt));
                    alert.setSummary(
                        String.format(
                            "%s suspicious account creation, %s %d",
                            monitoredResource, remoteAddress, cnt));
                    String buf = "";
                    for (String s : seenAcct) {
                      if (buf.isEmpty()) {
                        buf = s;
                      } else {
                        buf += ", " + s;
                      }
                    }
                    alert.addMetadata("email", buf);
                    if (accountAbuseSuppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(accountAbuseSuppressRecovery, alert);
                    }
                    c.output(alert);
                  }
                }))
        .apply("account creation global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
