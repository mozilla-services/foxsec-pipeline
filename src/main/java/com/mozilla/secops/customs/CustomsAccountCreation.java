package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Parser;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/** {@link DoFn} for analysis of account creation abuse applied to sessions */
public class CustomsAccountCreation extends DoFn<KV<String, Iterable<Event>>, KV<String, Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final int sessionCreationLimit;
  private final String monitoredResource;
  private final Integer accountAbuseSuppressRecovery;

  /**
   * Create new CustomsAccountCreation
   *
   * @param monitoredResource Monitored resource indicator
   * @param sessionCreationLimit Number of creations after which an alert is generated
   * @param accountAbuseSuppressRecovery Optional recovery suppression metadata to add for IprepdIO
   */
  public CustomsAccountCreation(
      String monitoredResource,
      Integer sessionCreationLimit,
      Integer accountAbuseSuppressRecovery) {
    this.monitoredResource = monitoredResource;
    this.sessionCreationLimit = sessionCreationLimit;
    this.accountAbuseSuppressRecovery = accountAbuseSuppressRecovery;
  }

  public String getTransformDoc() {
    return String.format(
        "Alert if single source address creates %d or more accounts in one session, where a session"
            + " ends after 30 minutes of inactivity.",
        sessionCreationLimit);
  }

  /**
   * Filter input collection by account creation and key by source address
   *
   * <p>Returns a {@link PCollection} that contains account creation events keyed by the source
   * address of the event. Verifies at a minimum the source address and email fields are present in
   * the event.
   *
   * @param col Input collection
   * @return {@link PCollection} of account creation events, keyed by source address
   */
  public static PCollection<KV<String, Event>> keyCreationEvents(PCollection<Event> col) {
    return col.apply(
        "key creation events",
        ParDo.of(
            new DoFn<Event, KV<String, Event>>() {
              private static final long serialVersionUID = 1L;

              @ProcessElement
              public void processElement(ProcessContext c) {
                Event e = c.element();

                String remoteAddress = CustomsUtil.authGetSourceAddress(e);
                if (remoteAddress == null) {
                  return;
                }

                FxaAuth.EventSummary summary = CustomsUtil.authGetEventSummary(e);
                if (summary == null) {
                  return;
                }
                if (!summary.equals(FxaAuth.EventSummary.ACCOUNT_CREATE)) {
                  return;
                }

                Integer status = CustomsUtil.authGetStatus(e);
                if (status == null || status != 200) {
                  return;
                }

                if (CustomsUtil.authGetEmail(e) == null) {
                  return;
                }

                c.output(KV.of(remoteAddress, e));
              }
            }));
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    String remoteAddress = c.element().getKey();
    Iterable<Event> events = c.element().getValue();

    Boolean principalVariance = false;
    int createCount = 0;
    String seenPrincipal = null;
    ArrayList<String> seenCreateAccounts = new ArrayList<>();

    for (Event e : events) {
      String email = CustomsUtil.authGetEmail(e);
      seenCreateAccounts.add(email);
      createCount++;

      if (seenPrincipal == null) {
        seenPrincipal = email;
      } else {
        if (!seenPrincipal.equals(email)) {
          principalVariance = true;
        }
      }
    }

    if ((createCount < sessionCreationLimit) || !principalVariance) {
      // The number of accounts created did not hit the limit value, or the events were
      // all for the same account
      return;
    }

    Alert alert = new Alert();
    alert.setTimestamp(Parser.getLatestTimestamp(events));
    alert.setCategory("customs");
    alert.setNotifyMergeKey(Customs.CATEGORY_ACCOUNT_CREATION_ABUSE);
    alert.addMetadata("customs_category", Customs.CATEGORY_ACCOUNT_CREATION_ABUSE);
    alert.addMetadata("sourceaddress", remoteAddress);
    alert.addMetadata("count", Integer.toString(createCount));
    alert.setSummary(
        String.format(
            "%s suspicious account creation, %s %d",
            monitoredResource, remoteAddress, createCount));
    String buf = "";
    for (String s : seenCreateAccounts) {
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
    c.output(KV.of(remoteAddress, alert));
  }
}
