package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.customs.CustomsAtRiskAccountState.CustomsAtRiskAccountStateModel;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import com.mozilla.secops.window.GlobalTriggers;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Flag failed logins to potentially at risk accounts.
 *
 * <p>Requires Datastore for state.
 */
public class CustomsLoginFailureForAtRiskAccount
    extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;

  private final Logger log = LoggerFactory.getLogger(CustomsLoginFailureForAtRiskAccount.class);

  /** Datastore namespace used for state */
  public static final String DATASTORE_NAMESPACE = "customs_lfara";

  /** Datastore kind used for state */
  public static final String DATASTORE_KIND = "customs_lfara";

  private boolean escalate;

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return "Generate alerts if there are failed logins on an account previously flagged "
        + "as at risk by the status comparator.";
  }

  /**
   * Create new CustomsLoginFailureForAtRiskAccount
   *
   * @param options Pipeline options
   */
  public CustomsLoginFailureForAtRiskAccount(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "login failure filter events",
            ParDo.of(
                new DoFn<Event, Event>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    FxaAuth.EventSummary sum = CustomsUtil.authGetEventSummary(e);

                    if (!(sum == FxaAuth.EventSummary.LOGIN_FAILURE)) {
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
            "login failure window",
            Window.<Event>into(FixedWindows.of(Duration.standardMinutes(5))))
        .apply(
            "login failure analyze",
            ParDo.of(
                new DoFn<Event, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private State state;

                  @Setup
                  public void setup() throws StateException {
                    log.info("using datastore for state management");
                    state =
                        new State(new DatastoreStateInterface(DATASTORE_KIND, DATASTORE_NAMESPACE));
                    state.initialize();
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    String ip = CustomsUtil.authGetSourceAddress(c.element());
                    String email = CustomsUtil.authGetEmail(c.element());

                    CustomsAtRiskAccountStateModel.ScannedByEntry ent = null;
                    try {
                      StateCursor<CustomsAtRiskAccountStateModel.ScannedByEntry> sc =
                          state.newCursor(
                              CustomsAtRiskAccountStateModel.ScannedByEntry.class, false);
                      ent = sc.get(email);
                    } catch (StateException exc) {
                      log.error("error fetching lfara state: {}", exc.getMessage());
                      return;
                    }

                    if (ent == null) {
                      return;
                    }

                    // Make sure the entry timestamp isn't too old, if it is we will ignore it
                    if (ent.getTimestamp()
                        .isBefore(new DateTime().minus(Duration.standardDays(7L)))) {
                      log.info("ignoring expired state for {}", email);
                    }

                    Alert alert = new Alert();
                    alert.setCategory("customs");
                    alert.setSubcategory(Customs.CATEGORY_LOGIN_FAILURE_AT_RISK_ACCOUNT);
                    alert.setNotifyMergeKey(Customs.CATEGORY_LOGIN_FAILURE_AT_RISK_ACCOUNT);
                    alert.addMetadata(AlertMeta.Key.EMAIL, email);
                    alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, ip);
                    alert.setSummary(
                        String.format(
                            "%s login failure for at risk account, %s", monitoredResource, ip));

                    c.output(alert);
                  }
                }))
        .apply("login failure global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
