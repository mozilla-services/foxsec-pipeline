package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.authstate.AuthStateModel;
import com.mozilla.secops.authstate.PruningStrategyLatest;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
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

/** Customs location velocity analysis */
public class CustomsVelocity extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  public static final String VELOCITY_KIND = "customs_velocity";

  private final Double maxKilometersPerSecond;

  private final String memcachedHost;
  private final Integer memcachedPort;
  private final String datastoreNamespace;
  private final Logger log = LoggerFactory.getLogger(CustomsVelocity.class);

  public String getTransformDoc() {
    return String.format(
        "Alert based on applying location velocity analysis to FxA events,"
            + " using a maximum KM/s of %.2f",
        maxKilometersPerSecond);
  }

  /**
   * Initialize new CustomsVelocity
   *
   * @param options Pipeline options
   */
  public CustomsVelocity(Customs.CustomsOptions options) {
    maxKilometersPerSecond = options.getMaximumKilometersPerHour() / 3600.0;
    memcachedHost = options.getMemcachedHost();
    memcachedPort = options.getMemcachedPort();
    datastoreNamespace = options.getDatastoreNamespace();
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "velocity filter events",
            ParDo.of(
                new DoFn<Event, KV<String, Event>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    FxaAuth.EventSummary sum = CustomsUtil.authGetEventSummary(e);
                    // Filter certain classes of high volume events here
                    if ((sum == FxaAuth.EventSummary.ACCOUNT_STATUS_CHECK)
                        || (sum == FxaAuth.EventSummary.DEVICES_LIST)) {
                      return;
                    }

                    // If no path was present in the request, also filter that here
                    if (CustomsUtil.authGetPath(e) == null) {
                      return;
                    }

                    // Consider anything that has both a UID and a source address
                    String uid = CustomsUtil.authGetUid(e);
                    if (uid == null) {
                      return;
                    }
                    if (CustomsUtil.authGetSourceAddress(e) == null) {
                      return;
                    }

                    c.output(KV.of(uid, e));
                  }
                }))
        .apply(
            "velocity window",
            Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(5))))
        .apply("velocity gbk", GroupByKey.<String, Event>create())
        .apply(
            "velocity analyze",
            ParDo.of(
                new DoFn<KV<String, Iterable<Event>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private State state;

                  @Setup
                  public void setup() throws StateException {
                    if (memcachedHost != null && memcachedPort != null) {
                      log.info("using memcached for state management");
                      state = new State(new MemcachedStateInterface(memcachedHost, memcachedPort));
                    } else if (datastoreNamespace != null) {
                      log.info("using datastore for state management");
                      state =
                          new State(new DatastoreStateInterface(VELOCITY_KIND, datastoreNamespace));
                    } else {
                      throw new IllegalArgumentException(
                          "could not find valid state parameters in options");
                    }
                    state.initialize();
                  }

                  @Teardown
                  public void teardown() {
                    state.done();
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    String uid = c.element().getKey();
                    Iterable<Event> events = c.element().getValue();

                    ArrayList<String> seenAddr = new ArrayList<>();

                    for (Event e : events) {
                      String remoteAddress = CustomsUtil.authGetSourceAddress(e);
                      String email = CustomsUtil.authGetEmail(e);
                      Double longitude = CustomsUtil.authGetSourceAddressLongitude(e);
                      Double latitude = CustomsUtil.authGetSourceAddressLatitude(e);
                      if ((remoteAddress == null)
                          || (latitude == null)
                          || (longitude == null)
                          || (email == null)) {
                        continue;
                      }

                      // Just process each address once per window
                      if (seenAddr.contains(remoteAddress)) {
                        continue;
                      }
                      seenAddr.add(remoteAddress);

                      StateCursor cur = state.newCursor();

                      AuthStateModel sm = null;
                      try {
                        sm = AuthStateModel.get(uid, cur, new PruningStrategyLatest());
                        if (sm == null) {
                          sm = new AuthStateModel(uid);
                        }
                      } catch (StateException exc) {
                        log.error("error reading from state: {}", exc.getMessage());
                        return;
                      }

                      // Update the state entry; we want to use the timestamp on the event here
                      if (!sm.updateEntry(remoteAddress, e.getTimestamp(), latitude, longitude)) {
                        // Address was already seen, so just update the state and continue
                        try {
                          sm.set(cur, new PruningStrategyLatest());
                        } catch (StateException exc) {
                          log.error("error updating state: {}", exc.getMessage());
                          return;
                        }
                        continue;
                      }

                      AuthStateModel.GeoVelocityResponse geoResp =
                          sm.geoVelocityAnalyzeLatest(maxKilometersPerSecond);

                      if (geoResp != null) {
                        log.info(
                            "{}: new location is {}km away from last location within {}s",
                            uid,
                            geoResp.getKmDistance(),
                            geoResp.getTimeDifference());
                        if (geoResp.getMaxKmPerSecondExceeded()) {
                          log.info("{}: creating velocity alert", uid);
                          Alert alert = new Alert();
                          alert.setCategory("customs");
                          alert.setTimestamp(e.getTimestamp());
                          alert.setNotifyMergeKey(Customs.CATEGORY_VELOCITY);
                          alert.addMetadata("sourceaddress", remoteAddress);
                          alert.addMetadata("uid", uid);
                          alert.addMetadata("email", email);
                          alert.setSummary(
                              String.format(
                                  "%s velocity exceeded, %.2f km in %d seconds",
                                  uid, geoResp.getKmDistance(), geoResp.getTimeDifference()));
                          c.output(alert);
                        }
                      }

                      try {
                        sm.set(cur, new PruningStrategyLatest());
                      } catch (StateException exc) {
                        log.error("error updating state: {}", exc.getMessage());
                      }
                    }
                  }
                }))
        .apply("velocity global windows", new GlobalTriggers<Alert>(5));
  }
}
