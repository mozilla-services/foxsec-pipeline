package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/** Report on request restrictions in AMO */
public class ReportRestriction extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;

  /**
   * Create new ReportRestriction
   *
   * @param monitoredResource Monitored resource indicator
   */
  public ReportRestriction(String monitoredResource) {
    this.monitoredResource = monitoredResource;
  }

  /** Transform documentation for users - see {@link com.mozilla.secops.DocumentingTransform} */
  public String getTransformDoc() {
    return "Reports on request restrictions from AMO";
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply("report restriction window", new GlobalTriggers<Event>(5))
        .apply(
            "report restriction",
            ParDo.of(
                new DoFn<Event, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    if (!e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                      return;
                    }
                    AmoDocker d = e.getPayload();
                    if (d.getEventType() == null) {
                      return;
                    }
                    if (!d.getEventType().equals(AmoDocker.EventType.RESTRICTED)) {
                      return;
                    }

                    Alert alert = new Alert();
                    alert.setCategory("amo");
                    alert.setSubcategory("amo_restriction");
                    alert.setNotifyMergeKey("amo_restriction");
                    alert.addMetadata("sourceaddress", d.getRemoteIp());
                    alert.addMetadata("restricted_value", d.getRestrictedValue());
                    alert.setSummary(
                        String.format(
                            "%s request to amo from %s restricted based on reputation",
                            monitoredResource, d.getRestrictedValue()));
                    c.output(alert);
                  }
                }));
  }
}
