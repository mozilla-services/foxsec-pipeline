package com.mozilla.secops.whitelistedips;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateException;
import org.apache.beam.sdk.transforms.DoFn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** */
public class WhitelistedIpsLabeler extends DoFn<String, String> {
  private static final long serialVersionUID = 1L;
  private final Logger log;
  private State state;

  private static final String datastoreKind = "whitelisted_ip";
  private static final String defaultNamespace = "";

  public WhitelistedIpsLabeler() {
    log = LoggerFactory.getLogger(WhitelistedIpsLabeler.class);
    state = new State(new DatastoreStateInterface(datastoreKind, defaultNamespace));
    try {
      state.initialize();
    } catch (StateException exc) {
      log.error("error initializing state: {}", exc.getMessage());
    }
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    String el = c.element();
    Alert a = Alert.fromJSON(el);
    if (a == null) {
      return;
    }

    String ip = a.getMetadataValue("sourceaddress");
    if (ip != null && inWhitelist(ip)) {
      a.addMetadata("iprepd_exempt", "true");
    }
    c.output(a.toJSON());
  }

  private Boolean inWhitelist(String ip) {
    try {
      WhitelistedIp wip = state.get(ip, WhitelistedIp.class);
      if (wip == null) {
        return false;
      }
      return true;
    } catch (StateException exc) {
      log.error("error getting whitelisted ip: {}", exc.getMessage());
      return false;
    }
  }
}
