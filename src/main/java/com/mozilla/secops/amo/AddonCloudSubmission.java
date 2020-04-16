package com.mozilla.secops.amo;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/** Alert on add-on submissions from cloud providers */
public class AddonCloudSubmission extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;

  /**
   * Construct new AddonCloudSubmission
   *
   * @param monitoredResource Monitored resource indicator
   */
  public AddonCloudSubmission(String monitoredResource) {
    this.monitoredResource = monitoredResource;
  }

  public String getTransformDoc() {
    return "Alert on add-on submissions from cloud providers.";
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply("addon cloud submission global triggers", new GlobalTriggers<Event>(5))
        .apply(
            "addon cloud submission",
            ParDo.of(
                new DoFn<Event, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private CidrUtil awsCidr;
                  private CidrUtil gcpCidr;

                  @Setup
                  public void setup() throws IOException {
                    awsCidr = new CidrUtil();
                    awsCidr.loadAwsSubnets();
                    gcpCidr = new CidrUtil();
                    gcpCidr.loadGcpSubnets();
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    if (!e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                      return;
                    }
                    AmoDocker d = e.getPayload();
                    if ((d == null) || (d.getEventType() == null)) {
                      return;
                    }
                    if (!d.getEventType().equals(AmoDocker.EventType.NEWVERSION)) {
                      return;
                    }

                    String f = null;
                    if (awsCidr.contains(d.getRemoteIp())) {
                      f = "aws";
                    } else if (gcpCidr.contains(d.getRemoteIp())) {
                      f = "gcp";
                    } else {
                      return;
                    }

                    Alert alert = new Alert();
                    alert.setCategory("amo");
                    alert.setSubcategory("amo_cloud_submission");
                    alert.setNotifyMergeKey("amo_cloud_submission");
                    alert.addMetadata(AlertMeta.Key.PROVIDER, f);
                    alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, d.getRemoteIp());
                    if (d.getAddonGuid() != null) {
                      alert.addMetadata(AlertMeta.Key.ADDON_GUID, d.getAddonGuid());
                    }
                    if (d.getFxaEmail() != null) {
                      alert.addMetadata(AlertMeta.Key.EMAIL, d.getFxaEmail());
                    }
                    alert.setSummary(
                        String.format(
                            "%s cloud provider addon submission from %s, guid %s",
                            monitoredResource,
                            d.getRemoteIp(),
                            d.getAddonGuid() != null ? d.getAddonGuid() : "unknown"));
                    c.output(alert);
                  }
                }));
  }
}
