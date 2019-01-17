package com.mozilla.secops.alert;

import com.mozilla.secops.OutputOptions;
import org.apache.beam.sdk.transforms.DoFn;

/**
 * {@link DoFn} for conversion of {@link Alert} objects into JSON strings
 *
 * <p>This DoFn also supplements the alert with a metadata entry with the monitored resource
 * indicator value, which is a required value in {@link OutputOptions}.
 */
public class AlertFormatter extends DoFn<Alert, String> {
  private static final long serialVersionUID = 1L;

  private String monitoredResourceIndicator;

  public AlertFormatter(OutputOptions options) {
    monitoredResourceIndicator = options.getMonitoredResourceIndicator();
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Alert a = c.element();
    a.addMetadata("monitored_resource", monitoredResourceIndicator);
    c.output(a.toJSON());
  }
}
