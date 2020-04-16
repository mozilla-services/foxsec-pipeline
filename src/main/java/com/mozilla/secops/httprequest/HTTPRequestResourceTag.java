package com.mozilla.secops.httprequest;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import org.apache.beam.sdk.transforms.DoFn;

/**
 * Add monitored resource indicator
 *
 * <p>Performs a similar function to AlertFormatter, however is intended for use with partitioned
 * per-service pipelines
 */
public class HTTPRequestResourceTag extends DoFn<Alert, Alert> {
  private static final long serialVersionUID = 1L;

  private final String monitoredResourceIndicator;

  /**
   * Create new HTTPRequestResourceTag
   *
   * @param name Name to assign to monitored_resource
   */
  public HTTPRequestResourceTag(String name) {
    monitoredResourceIndicator = name;
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Alert a = c.element();
    a.addMetadata(AlertMeta.Key.MONITORED_RESOURCE, monitoredResourceIndicator);
    c.output(a);
  }
}
