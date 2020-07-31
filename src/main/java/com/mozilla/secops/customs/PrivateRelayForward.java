package com.mozilla.secops.customs;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.PrivateRelay;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Private relay forwarding analysis
 *
 * <p>This transform will analyze private relay forward notifications in addition to FxA RP
 * callbacks indicating a change of the account email address. This information is used to populate
 * a state cache that maps the UID to a hashed version of the forwarding address.
 *
 * <p>If a forwarding event is observed that shows a hashed real address that differs from the one
 * the system knows about for a given UID, an alert will be generated.
 */
public class PrivateRelayForward extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  /** Datastore namespace for state */
  public static final String DATASTORE_NAMESPACE = "private_relay_forward";

  /** Datastore kind for state */
  public static final String DATASTORE_KIND = "private_relay_forward";

  private final String monitoredResource;
  private final Logger log = LoggerFactory.getLogger(PrivateRelayForward.class);

  /** PrivateRelayForwardState describes the format of individual state entries */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class PrivateRelayForwardState {
    private String uid;
    private String realAddress;

    /**
     * Get UID
     *
     * @return String
     */
    public String getUid() {
      return uid;
    }

    /**
     * Set UID
     *
     * @param uid String
     */
    @JsonProperty("uid")
    public void setUid(String uid) {
      this.uid = uid;
    }

    /**
     * Get real address
     *
     * @return String
     */
    public String getRealAddress() {
      return realAddress;
    }

    /**
     * Set real address
     *
     * @param realAddress String
     */
    @JsonProperty("real_address")
    public void setRealAddress(String realAddress) {
      this.realAddress = realAddress;
    }
  }

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return "Identify inconsistencies in private relay forward events using the forward"
        + "events themselves in addition to FxA email change RP callbacks.";
  }

  /**
   * Initialize new PrivateRelayForward
   *
   * @param options Pipeline options
   */
  public PrivateRelayForward(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "private relay filter events",
            ParDo.of(
                new DoFn<Event, KV<String, Event>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    PrivateRelay d = e.getPayload();
                    if (!d.getEventType().equals(PrivateRelay.EventType.EMAIL_RELAY)
                        && !d.getEventType().equals(PrivateRelay.EventType.FXA_RP_EVENT)) {
                      return;
                    }
                    // We need to have a UID to proceed with the event
                    if (d.getUid() == null) {
                      return;
                    }
                    c.output(KV.of(d.getUid(), e));
                  }
                }))
        .apply(
            "private relay window",
            Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(1))))
        .apply("private relay gbk", GroupByKey.<String, Event>create())
        .apply(
            "private relay analyze",
            ParDo.of(
                new DoFn<KV<String, Iterable<Event>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private State state;

                  @Setup
                  public void setup() throws IOException, StateException {
                    log.info("using datastore for state management");
                    state =
                        new State(
                            new DatastoreStateInterface(
                                PrivateRelayForward.DATASTORE_KIND,
                                PrivateRelayForward.DATASTORE_NAMESPACE));
                    state.initialize();
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    String uid = c.element().getKey();
                    // Sort our input by timestamp
                    List<Event> events =
                        StreamSupport.stream(c.element().getValue().spliterator(), false)
                            .sorted((e1, e2) -> e1.getTimestamp().compareTo(e2.getTimestamp()))
                            .collect(Collectors.toList());

                    StateCursor<PrivateRelayForwardState> curs;
                    try {
                      curs = state.newCursor(PrivateRelayForwardState.class, false);
                    } catch (StateException exc) {
                      log.error("error creating state cursor: {}", exc.getMessage());
                      return;
                    }

                    for (Event e : events) {
                      // Fetch any existing state for this UID, it's possible this will return
                      // null if no state is known for a given UID
                      PrivateRelayForwardState prfs;
                      try {
                        prfs = curs.get(uid);
                      } catch (StateException exc) {
                        log.error("error fetching state for {}: {}", uid, exc.getMessage());
                        return;
                      }
                      if (prfs == null) {
                        // No state for the UID was found, so initialize a new state instance but
                        // don't set the real address value which will indicate it is new
                        prfs = new PrivateRelayForwardState();
                        prfs.setUid(uid);
                      }

                      PrivateRelay d = e.getPayload();

                      // If this is an RP event, we simply need to update the existing state with
                      // a new real address value
                      if (d.getEventType().equals(PrivateRelay.EventType.FXA_RP_EVENT)) {
                        prfs.setRealAddress(d.getRealAddress());
                        log.info("updating real_address for {} using rp event", uid);
                        try {
                          curs.set(uid, prfs);
                        } catch (StateException exc) {
                          log.error(
                              "error updating state for {} on rp event: {}", uid, exc.getMessage());
                        }
                        continue;
                      }

                      // Otherwise, this is a forward event. Make sure the real address value
                      // matches the value pulled from state. If the state is new (it did
                      // not exist) we will set the real address value in state based on
                      // the value in the forward event.
                      if (prfs.getRealAddress() == null) {
                        log.info("updating real_address for {} using relay event", uid);
                        prfs.setRealAddress(d.getRealAddress());
                        try {
                          curs.set(uid, prfs);
                        } catch (StateException exc) {
                          log.error(
                              "error updating state for {} on forward event (new): {}",
                              uid,
                              exc.getMessage());
                        }
                      } else if (!prfs.getRealAddress().equals(d.getRealAddress())) {
                        log.info("real address hash mismatch for {}", uid);
                        Alert a = new Alert();
                        a.setCategory("customs");
                        a.setNotifyMergeKey(Customs.CATEGORY_PRIVATE_RELAY_FORWARD);
                        a.setSubcategory(Customs.CATEGORY_PRIVATE_RELAY_FORWARD);
                        a.addMetadata(AlertMeta.Key.UID, uid);
                        a.addMetadata(AlertMeta.Key.REAL_ADDRESS_HASH_ACTUAL, d.getRealAddress());
                        a.addMetadata(
                            AlertMeta.Key.REAL_ADDRESS_HASH_EXPECTED, prfs.getRealAddress());
                        a.setSummary(
                            String.format(
                                "%s private relay address hash mismatch for %s",
                                monitoredResource, uid));

                        prfs.setRealAddress(d.getRealAddress());
                        try {
                          curs.set(uid, prfs);
                        } catch (StateException exc) {
                          log.error(
                              "error updating state for {} on forward event (mismatch): {}",
                              uid,
                              exc.getMessage());
                        }

                        c.output(a);
                      }
                    }
                  }
                }))
        .apply("private relay global windows", new GlobalTriggers<Alert>(5));
  }

  /** {@inheritDoc} */
  public boolean isExperimental() {
    // This transform doesn't escalate to FxA, but return false here so we don't end up
    // with an experimental flag in the transform doc.
    return false;
  }
}
