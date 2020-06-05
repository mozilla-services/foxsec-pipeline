package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.window.GlobalTriggers;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomsLoginFailureForAtRiskAccount
    extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;

  private final Logger log = LoggerFactory.getLogger(CustomsLoginFailureForAtRiskAccount.class);

  private boolean escalate;

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return "Generate alerts if there are failed logins on an account previously flagged as at risk by the status comparator.";
  }

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

                  @ProcessElement
                  public void processElement(ProcessContext c) {}
                }))
        .apply("login failure global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
