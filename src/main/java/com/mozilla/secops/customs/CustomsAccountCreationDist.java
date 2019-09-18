package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.StringDistance;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;

/** {@link DoFn} for analysis of distributed account creation abuse */
public class CustomsAccountCreationDist extends DoFn<KV<String, Iterable<Event>>, Alert>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final int ratioAlertCount;
  private final Double ratioConsiderationUpper;
  private final String monitoredResource;

  /**
   * Create new CustomsAccountCreationDist
   *
   * @param monitoredResource Monitored resource indicator
   * @param ratioAlertCount Alert if matching similar account count meets or exceeds value
   * @param ratioConsiderationUpper Upper bounds for string distance comparison alerting
   */
  public CustomsAccountCreationDist(
      String monitoredResource, Integer ratioAlertCount, Double ratioConsiderationUpper) {
    this.monitoredResource = monitoredResource;
    this.ratioAlertCount = ratioAlertCount;
    this.ratioConsiderationUpper = ratioConsiderationUpper;
  }

  public String getTransformDoc() {
    return String.format(
        "Alert if at least %s accounts are created from different source addresses in a 30 "
            + "minute time frame and the similarity index of the accounts is all below %.2f.",
        ratioAlertCount, ratioConsiderationUpper);
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    String domain = c.element().getKey();
    Iterable<Event> events = c.element().getValue();

    for (Event e : events) {
      String email = CustomsUtil.authGetEmail(e);
      String remoteAddress = CustomsUtil.authGetSourceAddress(e);

      Boolean addrVariance = false;
      ArrayList<String> cand = new ArrayList<>();
      for (Event f : events) {
        String candEmail = CustomsUtil.authGetEmail(f);
        if (candEmail.equals(email)) {
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

      if (cand.size() >= ratioAlertCount) {
        Alert alert = new Alert();
        alert.setCategory("customs");
        alert.setNotifyMergeKey("account_creation_abuse_distributed");
        alert.addMetadata("customs_category", "account_creation_abuse_distributed");
        alert.addMetadata("count", Integer.toString(cand.size() + 1));
        alert.addMetadata("sourceaddress", remoteAddress);
        alert.setSummary(
            String.format(
                "%s suspicious distributed account creation, %s %d",
                monitoredResource, remoteAddress, cand.size() + 1));
        alert.addMetadata("email", email);
        String buf = "";
        for (String s : cand) {
          if (buf.isEmpty()) {
            buf = s;
          } else {
            buf += ", " + s;
          }
        }
        alert.addMetadata("email_similar", buf);
        c.output(alert);
      }
    }
  }
}
