package com.mozilla.secops.metrics;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.parser.CfgTick;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import java.util.Map;
import org.apache.beam.sdk.transforms.DoFn;

/** Convert configuration ticks into alerts */
public class CfgTickProcessor extends DoFn<Event, Alert> {
  private static final long serialVersionUID = 1L;

  private String category;

  /**
   * Initialize new {@link CfgTickProcessor}
   *
   * @param category Category field to set on alert
   */
  public CfgTickProcessor(String category) {
    this.category = category;
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Event e = c.element();
    if (!(e.getPayloadType().equals(Payload.PayloadType.CFGTICK))) {
      return;
    }
    CfgTick ct = e.getPayload();
    if (ct == null) {
      return;
    }
    Map<String, String> configMap = ct.getConfigurationMap();
    if (configMap == null) {
      return;
    }

    Alert a = new Alert();
    a.setCategory(category);
    a.setSubcategory("cfgtick");
    a.setSummary("configuration tick");
    a.addMetadata(AlertMeta.Key.ALERTIO_IGNORE_EVENT, "true");
    for (Map.Entry<String, String> entry : configMap.entrySet()) {
      // We need to use custom metadata here since we are adding arbitrary keys
      a.addCustomMetadata(entry.getKey(), entry.getValue());
    }
    c.output(a);
  }
}
