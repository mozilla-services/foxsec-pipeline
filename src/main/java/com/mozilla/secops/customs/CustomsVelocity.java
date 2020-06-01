package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.authstate.AuthStateModel;
import com.mozilla.secops.authstate.PruningStrategyLatest;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.GeoIP;
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
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  public static final String VELOCITY_KIND = "customs_velocity";

  private final Double maxKilometersPerSecond;
  private final Double minimumDistanceForAlert;

  private final Double maxKilometersPerSecondMonitorOnly;
  private final Double minimumDistanceForAlertMonitorOnly;

  private final String memcachedHost;
  private final Integer memcachedPort;
  private final String datastoreNamespace;
  private final String monitoredResource;
  private final Logger log = LoggerFactory.getLogger(CustomsVelocity.class);

  private final String maxmindCityDbPath;
  private final String maxmindIspDbPath;

  private boolean escalate;
  private boolean checkExperimentalParam;

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    String checkExp = "";
    if (checkExperimentalParam) {
      String.format(
          ", monitor only alert using a maximum KM/s of %.2f", maxKilometersPerSecondMonitorOnly);
    }
    return String.format(
        "Alert based on applying location velocity analysis to FxA events,"
            + " using a maximum KM/s of %.2f%s",
        maxKilometersPerSecond, checkExp);
  }

  /**
   * Initialize new CustomsVelocity
   *
   * @param options Pipeline options
   */
  public CustomsVelocity(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
    maxKilometersPerSecond = options.getMaximumKilometersPerHour() / 3600.0;
    minimumDistanceForAlert = options.getMinimumDistanceForAlert();
    maxKilometersPerSecondMonitorOnly = options.getMaximumKilometersPerHourMonitorOnly() / 3600.0;
    minimumDistanceForAlertMonitorOnly = options.getMinimumDistanceForAlertMonitorOnly();
    checkExperimentalParam = options.getEnableVelocityDetectorMonitorOnly();
    memcachedHost = options.getMemcachedHost();
    memcachedPort = options.getMemcachedPort();
    datastoreNamespace = options.getDatastoreNamespace();

    maxmindCityDbPath = options.getMaxmindCityDbPath();
    maxmindIspDbPath = options.getMaxmindIspDbPath();

    escalate = options.getEscalateVelocity();
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
                    // Only look at login success here for now
                    if (!(sum == FxaAuth.EventSummary.LOGIN_SUCCESS)) {
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
                  private GeoIP geoip;

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
                    geoip = new GeoIP(maxmindCityDbPath, maxmindIspDbPath);
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

                      StateCursor<AuthStateModel> cur;
                      try {
                        cur = state.newCursor(AuthStateModel.class, true);
                      } catch (StateException exc) {
                        // Experimental, so log this as info for now. This could be expanded to
                        // error in the future.
                        log.info("error initializing state cursor: {}", exc.getMessage());
                        return;
                      }

                      AuthStateModel sm = null;
                      try {
                        sm = AuthStateModel.get(uid, cur, new PruningStrategyLatest());
                        if (sm == null) {
                          sm = new AuthStateModel(uid);
                        }
                      } catch (StateException exc) {
                        // Experimental, so log this as info for now. This could be expanded to
                        // error in the future.
                        log.info("error reading from state: {}", exc.getMessage());
                        return;
                      }

                      // Update the state entry; we want to use the timestamp on the event here
                      AuthStateModel.ModelEntryUpdate uRequest =
                          new AuthStateModel.ModelEntryUpdate();
                      uRequest.ipAddress = remoteAddress;
                      uRequest.timestamp = e.getTimestamp();
                      uRequest.latitude = latitude;
                      uRequest.longitude = longitude;
                      uRequest.userAgent = CustomsUtil.authGetUserAgent(e);
                      if (!sm.updateEntry(uRequest)) {
                        // Address was already seen, so just update the state and continue
                        try {
                          sm.set(cur, new PruningStrategyLatest());
                        } catch (StateException exc) {
                          log.info("error updating state: {}", exc.getMessage());
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

                        boolean minDistanceMet = true;
                        if (minimumDistanceForAlert != null) {
                          if (geoResp.getKmDistance() < minimumDistanceForAlert) {
                            log.info("{}: will skip alert as minimum distance was not met", uid);
                            minDistanceMet = false;
                          }
                        }

                        if (geoResp.getMaxKmPerSecondExceeded() && minDistanceMet) {
                          log.info("{}: creating velocity alert", uid);
                          Alert alert = new Alert();
                          alert.setCategory("customs");
                          alert.setSubcategory(Customs.CATEGORY_VELOCITY);
                          alert.setTimestamp(e.getTimestamp());
                          alert.setNotifyMergeKey(Customs.CATEGORY_VELOCITY);
                          alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);
                          alert.addMetadata(
                              AlertMeta.Key.SOURCEADDRESS_PREVIOUS, geoResp.getPreviousSource());
                          alert.addMetadata(
                              AlertMeta.Key.TIME_DELTA_SECONDS,
                              geoResp.getTimeDifference().toString());
                          alert.addMetadata(
                              AlertMeta.Key.KM_DISTANCE,
                              String.format("%.2f", geoResp.getKmDistance()));
                          alert.addMetadata(AlertMeta.Key.UID, uid);
                          alert.addMetadata(AlertMeta.Key.EMAIL, email);
                          alert.setSummary(
                              String.format(
                                  "%s %s velocity exceeded, %.2f km in %d seconds",
                                  monitoredResource,
                                  uid,
                                  geoResp.getKmDistance(),
                                  geoResp.getTimeDifference()));

                          // It's possible the AlertFormatter DoFn could add this for us later, but
                          // since it is important information as part of this transform make sure
                          // it will be present by leveraging the formatters GeoIP method here.
                          AlertFormatter.addGeoIPData(alert, geoip);

                          c.output(alert);
                        }

                        // for monitoring smaller velocity jumps than we escalate for
                        if (checkExperimentalParam) {
                          AuthStateModel.GeoVelocityResponse geoRespMO =
                              sm.geoVelocityAnalyzeLatest(maxKilometersPerSecondMonitorOnly);

                          if (geoRespMO != null) {
                            log.info(
                                "{}: new location is {}km away from last location within {}s",
                                uid,
                                geoRespMO.getKmDistance(),
                                geoRespMO.getTimeDifference());

                            boolean minDistanceMetMO = true;
                            if (minimumDistanceForAlertMonitorOnly != null) {
                              if (geoRespMO.getKmDistance() < minimumDistanceForAlertMonitorOnly) {
                                log.info(
                                    "{}: will skip alert as minimum distance was not met (monitor only)",
                                    uid);
                                minDistanceMet = false;
                              }
                            }

                            if (geoRespMO.getMaxKmPerSecondExceeded() && minDistanceMetMO) {
                              log.info("{}: creating velocity monitor only alert", uid);
                              Alert alertMO = new Alert();
                              alertMO.setCategory("customs");
                              alertMO.setSubcategory(Customs.CATEGORY_VELOCITY_MONITOR_ONLY);
                              alertMO.setTimestamp(e.getTimestamp());
                              alertMO.setNotifyMergeKey(Customs.CATEGORY_VELOCITY_MONITOR_ONLY);
                              alertMO.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);
                              alertMO.addMetadata(
                                  AlertMeta.Key.SOURCEADDRESS_PREVIOUS,
                                  geoResp.getPreviousSource());
                              alertMO.addMetadata(
                                  AlertMeta.Key.TIME_DELTA_SECONDS,
                                  geoResp.getTimeDifference().toString());
                              alertMO.addMetadata(
                                  AlertMeta.Key.KM_DISTANCE,
                                  String.format("%.2f", geoResp.getKmDistance()));
                              alertMO.addMetadata(AlertMeta.Key.UID, uid);
                              alertMO.addMetadata(AlertMeta.Key.EMAIL, email);
                              alertMO.setSummary(
                                  String.format(
                                      "%s %s velocity exceeded, %.2f km in %d seconds",
                                      monitoredResource,
                                      uid,
                                      geoRespMO.getKmDistance(),
                                      geoRespMO.getTimeDifference()));

                              // It's possible the AlertFormatter DoFn could add this for us
                              // later, but
                              // since it is important information as part of this transform make
                              // sure
                              // it will be present by leveraging the formatters GeoIP method
                              // here.
                              AlertFormatter.addGeoIPData(alertMO, geoip);

                              c.output(alertMO);
                            }
                          }
                        }
                      }

                      try {
                        sm.set(cur, new PruningStrategyLatest());
                      } catch (StateException exc) {
                        log.info("error updating state: {}", exc.getMessage());
                      }
                    }
                  }
                }))
        .apply("velocity global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
