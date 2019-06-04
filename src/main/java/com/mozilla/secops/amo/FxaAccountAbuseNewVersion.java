package com.mozilla.secops.amo;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.Serializable;
import java.util.ArrayList;
import org.apache.beam.sdk.state.StateSpec;
import org.apache.beam.sdk.state.StateSpecs;
import org.apache.beam.sdk.state.ValueState;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/** Correlation of AMO addon submission with abusive FxA account creation alerts */
public class FxaAccountAbuseNewVersion extends PTransform<PCollection<Event>, PCollection<Alert>> {
  private static final long serialVersionUID = 1L;

  /** Used for state storage within the {@link FxaAccountAbuseNewVersion} transform */
  public static class FxaAccountAbuseNewVersionState implements Serializable {
    private static final long serialVersionUID = 1L;

    /** List of suspected accounts maintained in state */
    public ArrayList<String> suspectedAccounts;

    /** List of suspected addresses maintained in state */
    public ArrayList<String> suspectedAddress;

    /** Initialize new state element */
    public FxaAccountAbuseNewVersionState() {
      suspectedAccounts = new ArrayList<String>();
      suspectedAddress = new ArrayList<String>();
    }
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply("fxa account abuse new version window", new GlobalTriggers<Event>(5))
        .apply(
            "fxa account abuse new version filter applicable",
            ParDo.of(
                new DoFn<Event, Event>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    if (e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                      AmoDocker d = e.getPayload();
                      if ((d == null) || (d.getEventType() == null)) {
                        return;
                      }
                      if ((d.getEventType().equals(AmoDocker.EventType.NEWVERSION))
                          || (d.getEventType().equals(AmoDocker.EventType.GOTPROFILE))) {
                        c.output(e);
                        return;
                      }
                    } else if (e.getPayloadType().equals(Payload.PayloadType.ALERT)) {
                      com.mozilla.secops.parser.Alert d = e.getPayload();
                      Alert a = d.getAlert();
                      if (a.getCategory().equals("customs")
                          && a.getMetadataValue("customs_category")
                              .equals("account_creation_abuse")) {
                        c.output(e);
                        return;
                      }
                    }
                  }
                }))
        .apply(
            "fxa account abuse new version key for state",
            ParDo.of(
                new DoFn<Event, KV<Integer, Event>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    // Set pseudo-key for state usage, this is a low volume stream so should have
                    // minimal performance implications
                    c.output(KV.of(new Integer(0), c.element()));
                  }
                }))
        .apply(
            "fxa account abuse new version",
            ParDo.of(
                new DoFn<KV<Integer, Event>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @StateId("state")
                  private final StateSpec<ValueState<FxaAccountAbuseNewVersionState>> nvState =
                      StateSpecs.value();

                  @ProcessElement
                  public void processElement(
                      ProcessContext c,
                      @StateId("state") ValueState<FxaAccountAbuseNewVersionState> state) {
                    Event e = c.element().getValue();

                    if (e.getPayloadType().equals(Payload.PayloadType.ALERT)) {
                      // Contains a suspected account list, do a state fetch and update
                      FxaAccountAbuseNewVersionState s = state.read();
                      if (s == null) {
                        s = new FxaAccountAbuseNewVersionState();
                      }

                      com.mozilla.secops.parser.Alert d = e.getPayload();
                      Alert a = d.getAlert();
                      String acctbuf = a.getMetadataValue("email");
                      if (acctbuf == null) {
                        return;
                      }
                      String parts[] = acctbuf.split(", ?");
                      for (String i : parts) {
                        s.suspectedAccounts.add(i);
                      }
                      state.write(s);
                      return;
                    }

                    // If it wasn't an alert it will be an AMO event, see if we can map an address
                    // to the list of suspected accounts based on a profile fetch
                    if (!e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                      return;
                    }

                    FxaAccountAbuseNewVersionState s = state.read();
                    if (s == null) {
                      s = new FxaAccountAbuseNewVersionState();
                    }

                    AmoDocker d = e.getPayload();
                    if (d.getEventType().equals(AmoDocker.EventType.GOTPROFILE)) {
                      if (s.suspectedAccounts.contains(d.getFxaEmail())) {
                        s.suspectedAddress.add(d.getRemoteIp());
                        state.write(s);

                        // Also create an alert for the event
                        Alert alert = new Alert();
                        alert.setCategory("amo");
                        alert.setNotifyMergeKey("fxa_account_abuse_new_version_login");
                        alert.addMetadata("sourceaddress", d.getRemoteIp());
                        alert.addMetadata("email", d.getFxaEmail());
                        alert.addMetadata("amo_category", "fxa_account_abuse_new_version_login");
                        c.output(alert);
                        return;
                      }
                    } else if (d.getEventType().equals(AmoDocker.EventType.NEWVERSION)) {
                      if (!s.suspectedAddress.contains(d.getRemoteIp())) {
                        return;
                      }
                      // Address was in the suspected address list
                      Alert alert = new Alert();
                      alert.setCategory("amo");
                      alert.setNotifyMergeKey("fxa_account_abuse_new_version_submission");
                      alert.addMetadata("sourceaddress", d.getRemoteIp());
                      alert.addMetadata("amo_category", "fxa_account_abuse_new_version_submission");
                      alert.addMetadata("addon_id", d.getAddonId());
                      alert.addMetadata("addon_version", d.getAddonVersion());
                      c.output(alert);
                    }
                  }
                }));
  }
}
