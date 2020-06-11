package com.mozilla.secops.customs;

import com.mozilla.secops.FileUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Customs activity monitor for specified accounts
 *
 * <p>Requires list of monitored user accounts
 */
public class CustomsActivityForMonitoredAccounts
    extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final String accountsPath;

  private final Logger log = LoggerFactory.getLogger(CustomsActivityForMonitoredAccounts.class);

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return "Generate pipeline alerts if a monitored user has FxA activity";
  }

  /**
   * Initialize new CustomsActivityForMonitoredAccounts
   *
   * @param options Pipeline options
   */
  public CustomsActivityForMonitoredAccounts(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
    accountsPath = options.getActivityMonitorAccountPath();
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "activity monitor filter events",
            ParDo.of(
                new DoFn<Event, Event>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    FxaAuth.EventSummary sum = CustomsUtil.authGetEventSummary(e);

                    // Filter based on event type
                    if (!(sum == FxaAuth.EventSummary.LOGIN_SUCCESS)) {
                      return;
                    }

                    if (CustomsUtil.authGetSourceAddress(e) == null) {
                      return;
                    }

                    if (CustomsUtil.authGetEmail(e) == null) {
                      return;
                    }

                    c.output(e);
                  }
                }))
        .apply(
            "activity monitor window",
            Window.<Event>into(FixedWindows.of(Duration.standardMinutes(5))))
        .apply(
            "activity monitor analyze",
            ParDo.of(
                new DoFn<Event, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private ArrayList<String> accountlist;

                  @Setup
                  public void setup() throws IOException {
                    log.info("loading address list from {}", accountsPath);
                    accountlist = FileUtil.fileReadLines(accountsPath);
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();
                    String email = CustomsUtil.authGetEmail(e);
                    String address = CustomsUtil.authGetSourceAddress(e);

                    if (!accountlist.contains(email)) {
                      return;
                    }
                    log.info("activity monitor match for {} from {}", email, address);
                    FxaAuth.EventSummary sum = CustomsUtil.authGetEventSummary(e);

                    Alert alert = new Alert();
                    alert.setCategory("customs");
                    alert.setSubcategory(Customs.CATEGORY_ACTIVITY_MONITOR);
                    alert.setNotifyMergeKey(Customs.CATEGORY_ACTIVITY_MONITOR);
                    alert.addMetadata(AlertMeta.Key.EMAIL, email);
                    alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, address);
                    alert.setSummary(
                        String.format(
                            "%s activity on monitored account - action %s",
                            monitoredResource, sum));

                    c.output(alert);
                  }
                }))
        .apply("activity monitor global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return true;
  }
}
