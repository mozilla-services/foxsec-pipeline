package com.mozilla.secops.customs;

import com.mozilla.secops.StringDistance;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.customs.Customs.CustomsOptions;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/**
 * Abusive distributed account creation
 *
 * <p>Analysis of distributed account creation where accounts created meet a certain similarity
 * index.
 *
 * <p>Assumed to operate on fixed 10 minute windows.
 */
public class CustomsAccountCreationDist
    extends PTransform<PCollection<KV<String, CustomsFeatures>>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final int threshold;
  private final Double ratioConsiderationUpper;
  private final String monitoredResource;
  private final boolean escalate;

  /**
   * Create new CustomsAccountCreationDist
   *
   * @param options Pipeline options
   */
  public CustomsAccountCreationDist(CustomsOptions options) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    this.threshold = options.getAccountCreationDistributedThreshold();
    this.ratioConsiderationUpper = options.getAccountCreationDistributedDistanceRatio();
    this.escalate = options.getEscalateAccountCreationDistributed();
  }

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return String.format(
        "Alert if at least %d accounts are created from different source addresses in a 10 "
            + "minute fixed window and the similarity index of the accounts is all below %.2f.",
        threshold, ratioConsiderationUpper);
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, CustomsFeatures>> col) {
    return col.apply(
            "account creation distributed analyze",
            ParDo.of(
                new DoFn<KV<String, CustomsFeatures>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    CustomsFeatures cf = c.element().getValue();

                    if (cf.getTotalAccountCreateSuccess() < threshold) {
                      return;
                    }

                    String domain = c.element().getKey();
                    ArrayList<Event> events =
                        cf.getEventsOfType(FxaAuth.EventSummary.ACCOUNT_CREATE_SUCCESS);

                    for (Event e : events) {
                      String email = CustomsUtil.authGetEmail(e);
                      String remoteAddress = CustomsUtil.authGetSourceAddress(e);
                      if (email == null || remoteAddress == null) {
                        continue;
                      }

                      boolean addrVariance = false;
                      ArrayList<String> cand = new ArrayList<>();
                      for (Event f : events) {
                        String candEmail = CustomsUtil.authGetEmail(f);
                        if (candEmail == null || candEmail.equals(email)) {
                          continue;
                        }
                        if (StringDistance.ratio(email.split("@")[0], candEmail.split("@")[0])
                            <= ratioConsiderationUpper) {
                          if (!remoteAddress.equals(CustomsUtil.authGetSourceAddress(f))) {
                            addrVariance = true;
                          }
                          cand.add(candEmail);
                        }
                      }

                      // No variance in the source address we are done
                      if (!addrVariance) {
                        return;
                      }

                      if (cand.size() >= threshold) {
                        Alert alert = new Alert();
                        alert.setCategory("customs");
                        alert.setSubcategory(Customs.CATEGORY_ACCOUNT_CREATION_ABUSE_DIST);
                        alert.setNotifyMergeKey(Customs.CATEGORY_ACCOUNT_CREATION_ABUSE_DIST);
                        alert.addMetadata(AlertMeta.Key.COUNT, Integer.toString(cand.size() + 1));
                        alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);
                        alert.setSummary(
                            String.format(
                                "%s suspicious distributed account creation, %s %d",
                                monitoredResource, remoteAddress, cand.size() + 1));
                        alert.addMetadata(AlertMeta.Key.EMAIL, email);
                        String buf = "";
                        for (String s : cand) {
                          if (buf.isEmpty()) {
                            buf = s;
                          } else {
                            buf += ", " + s;
                          }
                        }
                        alert.addMetadata(AlertMeta.Key.EMAIL_SIMILAR, buf);
                        c.output(alert);
                      }
                    }
                  }
                }))
        .apply("account creation distributed global windows", new GlobalTriggers<Alert>(5));
  }

  @Override
  public boolean isExperimental() {
    return !escalate;
  }
}
