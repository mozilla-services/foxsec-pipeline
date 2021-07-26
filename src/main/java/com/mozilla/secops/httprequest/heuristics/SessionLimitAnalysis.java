package com.mozilla.secops.httprequest.heuristics;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.httprequest.HTTPRequestToggles;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transform for detection of a single source making excessive requests of a specific endpoint
 * pattern.
 *
 * <p>This is based on Endpoint Abuse Analysis but allows for pattern matching and monitor only
 * threshold.
 *
 * <p>Generates alerts where the request profile violates path thresholds specified in the
 * sessionLimitAnalysisPaths pipeline option configuration.
 */
public class SessionLimitAnalysis
    extends PTransform<PCollection<KV<String, ArrayList<String>>>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private Logger log;

  private final LimitInfo[] limits;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;
  private final Integer suppressRecovery;
  private final Long sessionGapDurationMinutes;
  private final Long alertSuppressionDurationSeconds;
  private final Boolean enableNatDetection;

  /** Internal class for configured endpoints */
  public static class LimitInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Request method */
    public String method;
    /** Request path pattern */
    public Pattern path;
    /** Threshold */
    public Integer threshold;
    /** Monitor */
    public Integer monitor;
  }

  /**
   * Static initializer for {@link SessionLimitAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   */
  public SessionLimitAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject) {
    log = LoggerFactory.getLogger(SessionLimitAnalysis.class);

    monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    suppressRecovery = toggles.getSessionLimitAnalysisSuppressRecovery();
    sessionGapDurationMinutes = toggles.getSessionGapDurationMinutes();
    alertSuppressionDurationSeconds = toggles.getAlertSuppressionDurationSeconds();
    enableNatDetection = toggles.getEnableNatDetection();

    String[] cfgLimits = toggles.getSessionLimitAnalysisPaths();

    if (cfgLimits.length > 1) {
      throw new IllegalArgumentException(
          "SessionLimitAnalysis currently only supports one monitored endpoint");
    }

    limits = new LimitInfo[cfgLimits.length];
    for (int i = 0; i < cfgLimits.length; i++) {
      String[] parts = cfgLimits[i].split(":");
      if (parts.length != 4) {
        throw new IllegalArgumentException(
            "invalid format for session limit path, must be <int>:<int>:<method>:<path>");
      }
      LimitInfo ninfo = new LimitInfo();
      ninfo.monitor = Integer.parseInt(parts[0]);
      ninfo.threshold = Integer.parseInt(parts[1]);
      ninfo.method = parts[2];
      ninfo.path = Pattern.compile(parts[3]);
      limits[i] = ninfo;

      if (ninfo.monitor > ninfo.threshold) {
        throw new IllegalArgumentException("monitor must be less than threshold");
      }
    }
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    String buf = null;
    for (int i = 0; i < limits.length; i++) {
      String x =
          String.format(
              "%d %s requests for %s. (monitor only: %d)",
              limits[i].threshold, limits[i].method, limits[i].path, limits[i].monitor);
      if (buf == null) {
        buf = x;
      } else {
        buf += " " + x;
      }
    }
    return String.format(
        "Clients are sessionized by address, where a session ends after "
            + "%d minutes of inactivity. An alert is generated if a client is observed "
            + "making repeated requests to configured endpoints. %s",
        sessionGapDurationMinutes, buf);
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, ArrayList<String>>> input) {
    return input
        .apply(GroupByKey.<String, ArrayList<String>>create())
        .apply(
            "analyze per-client",
            ParDo.of(
                new DoFn<KV<String, Iterable<ArrayList<String>>>, KV<String, Alert>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c, BoundedWindow w) {
                    String remoteAddress = c.element().getKey();
                    Iterable<ArrayList<String>> paths = c.element().getValue();
                    int[] limitCounter = new int[limits.length];
                    String userAgent = null;
                    HashMap<String, Boolean> uaMap = new HashMap<>();

                    // Used to track the latest applicable request, so we can use it as the
                    // alert timestamp if we need to generate an alert.
                    Instant latestRequest = null;

                    // Used to track earliest request in window whether or not it matches
                    // in order to provide insight into session length
                    Instant sessionStart = null;

                    // Count the number of requests in-window for this source that map to
                    // monitored endpoints.
                    for (ArrayList<String> i : paths) {

                      // always consider timestamp for session start
                      Instant t = Instant.parse(i.get(3));
                      if (sessionStart == null || t.getMillis() < sessionStart.getMillis()) {
                        sessionStart = t;
                      }

                      uaMap.put(i.get(2), true);

                      Integer abIdx = indexEndpoint(i.get(1), i.get(0));
                      if (abIdx != null) {
                        if (latestRequest == null || t.getMillis() > latestRequest.getMillis()) {
                          latestRequest = t;
                        }
                        // XXX Just pick up the user agent here; with agent variance this could
                        // result in a different agent being included in the alert than the one
                        // that was actually associated with the threshold violation.
                        userAgent = i.get(2);
                        limitCounter[abIdx]++;
                      }
                    }

                    if (enableNatDetection && uaMap.size() >= 2) {
                      log.info(
                          "detected NAT for {}, {} user agents present",
                          remoteAddress,
                          uaMap.size());
                      return;
                    }

                    // Identify if any
                    // monitored endpoints have exceeded the threshold and use the one with
                    // the highest request count
                    // TODO: this will likely need to be changed to allow for
                    // alerts on multiple paths in the same window
                    // currently we could miss an alert for an endpoint
                    // with a low limit, if there's a limit with
                    // a high monitor
                    Integer abmaxIndex = null;
                    int count = -1;
                    for (int i = 0; i < limits.length; i++) {
                      if (limits[i].monitor <= limitCounter[i]) {
                        if (abmaxIndex == null) {
                          abmaxIndex = i;
                          count = limitCounter[i];
                        } else {
                          if (count < limitCounter[i]) {
                            abmaxIndex = i;
                            count = limitCounter[i];
                          }
                        }
                      }
                    }

                    if (abmaxIndex == null) {
                      // No requests exceeded threshold
                      return;
                    }

                    log.info("{}: emitting alert for {} {}", w.toString(), remoteAddress, count);

                    String compareMethod = limits[abmaxIndex].method;
                    String comparePath = limits[abmaxIndex].path.toString();
                    Integer threshold = limits[abmaxIndex].threshold;
                    Integer monitor = limits[abmaxIndex].monitor;

                    Boolean isMonitorOnly = count < threshold;
                    String subcategory =
                        isMonitorOnly
                            ? "session_limit_analysis_monitor_only"
                            : "session_limit_analysis";
                    String thresholdValue =
                        isMonitorOnly ? Integer.toString(monitor) : Integer.toString(threshold);

                    Alert a = new Alert();
                    a.setTimestamp(latestRequest.toDateTime());
                    a.setSummary(
                        String.format(
                            "%s httprequest %s %s %s %s %d",
                            monitoredResource,
                            subcategory,
                            remoteAddress,
                            compareMethod,
                            comparePath,
                            count));
                    a.setCategory("httprequest");
                    a.setSubcategory(subcategory);
                    a.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);

                    try {
                      if (enableIprepdDatastoreExemptions) {
                        IprepdIO.addMetadataIfIpIsExempt(
                            remoteAddress, a, iprepdDatastoreExemptionsProject);
                      }
                    } catch (IOException exc) {
                      log.error("error checking iprepd exemptions: {}", exc.getMessage());
                      return;
                    }

                    if (suppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(suppressRecovery, a);
                    }

                    a.addMetadata(AlertMeta.Key.ENDPOINT, comparePath);
                    a.addMetadata(AlertMeta.Key.METHOD, compareMethod);
                    a.addMetadata(AlertMeta.Key.COUNT, Integer.toString(count));
                    a.addMetadata(AlertMeta.Key.THRESHOLD, thresholdValue);
                    a.addMetadata(AlertMeta.Key.USERAGENT, userAgent);
                    a.addMetadata(AlertMeta.Key.START, new DateTime(sessionStart).toString());

                    a.setNotifyMergeKey(String.format("%s %s", monitoredResource, subcategory));
                    a.addMetadata(
                        AlertMeta.Key.WINDOW_TIMESTAMP,
                        (new DateTime(w.maxTimestamp())).toString());
                    if (!a.hasCorrectFields()) {
                      throw new IllegalArgumentException("alert has invalid field configuration");
                    }
                    c.output(KV.of(remoteAddress, a));
                  }
                }))
        // Rewindow into global windows so we can use state in the next step
        //
        // Ideally we would apply state in the previous step, but this is not currently
        // supported by DataflowRunner.
        //
        // See also https://issues.apache.org/jira/browse/BEAM-2507
        .apply("session limit analysis global", new GlobalTriggers<KV<String, Alert>>(5))
        .apply(ParDo.of(new AlertSuppressorCount(alertSuppressionDurationSeconds)));
  }

  private Integer indexEndpoint(String path, String method) {
    for (int i = 0; i < limits.length; i++) {
      if ((limits[i].method.equals(method)) && (limits[i].path.matcher(path).matches())) {
        return i;
      }
    }
    return null;
  }
}
