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
 * Transform for detection of a single source making excessive requests of a specific endpoint path
 * solely.
 *
 * <p>Generates alerts where the request profile violates path thresholds specified in the
 * endpointAbusePath pipeline option configuration.
 */
public class EndpointAbuseAnalysis
    extends PTransform<PCollection<KV<String, ArrayList<String>>>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private Logger log;

  private final EndpointAbuseEndpointInfo[] endpoints;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final Boolean varianceSupportingOnly;
  private final String[] customVarianceSubstrings;
  private final String iprepdDatastoreExemptionsProject;
  private final Integer suppressRecovery;
  private final Long sessionGapDurationMinutes;
  private final Long alertSuppressionDurationSeconds;

  /** Internal class for configured endpoints in EPA */
  public static class EndpointAbuseEndpointInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Request method */
    public String method;
    /** Request path */
    public String path;
    /** Threshold */
    public Integer threshold;
  }

  /** Internal class for endpoint abuse state */
  public static class EndpointAbuseState implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Remote address */
    public String remoteAddress;
    /** Request count */
    public Integer count;
    /** Timestamp */
    public Instant timestamp;
  }

  /**
   * Static initializer for {@link EndpointAbuseAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   */
  public EndpointAbuseAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject) {
    log = LoggerFactory.getLogger(EndpointAbuseAnalysis.class);

    monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    varianceSupportingOnly = toggles.getEndpointAbuseExtendedVariance();
    suppressRecovery = toggles.getEndpointAbuseSuppressRecovery();
    customVarianceSubstrings = toggles.getEndpointAbuseCustomVarianceSubstrings();
    sessionGapDurationMinutes = toggles.getSessionGapDurationMinutes();
    alertSuppressionDurationSeconds = toggles.getAlertSuppressionDurationSeconds();

    String[] cfgEndpoints = toggles.getEndpointAbusePath();
    endpoints = new EndpointAbuseAnalysis.EndpointAbuseEndpointInfo[cfgEndpoints.length];
    for (int i = 0; i < cfgEndpoints.length; i++) {
      String[] parts = cfgEndpoints[i].split(":");
      if (parts.length != 3) {
        throw new IllegalArgumentException(
            "invalid format for abuse endpoint path, must be <int>:<method>:<path>");
      }
      EndpointAbuseAnalysis.EndpointAbuseEndpointInfo ninfo = new EndpointAbuseEndpointInfo();
      ninfo.threshold = Integer.parseInt(parts[0]);
      ninfo.method = parts[1];
      ninfo.path = parts[2];
      endpoints[i] = ninfo;
    }
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    String buf = null;
    for (int i = 0; i < endpoints.length; i++) {
      String x =
          String.format(
              "%d %s requests for %s.",
              endpoints[i].threshold, endpoints[i].method, endpoints[i].path);
      if (buf == null) {
        buf = x;
      } else {
        buf += " " + x;
      }
    }
    return String.format(
        "Clients are sessionized by address, where a session ends after "
            + "%d minutes of inactivity. An alert is generated if a client is observed "
            + "making repeated requests to configured endpoints without requesting other forms "
            + "of content from the site. %s",
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
                    int[] endCounter = new int[endpoints.length];
                    String userAgent = null;
                    boolean basicVariance = false;
                    boolean extendedVariance = false;

                    // Used to track the latest applicable EPA request, so we can use it as the
                    // alert timestamp if we need to generate an alert.
                    Instant latestEpaRequest = null;

                    // Count the number of requests in-window for this source that map to
                    // monitored endpoints. Set a basic variance flag if we see a request
                    // that was made to something that is not monitored.
                    for (ArrayList<String> i : paths) {
                      Integer abIdx = indexEndpoint(i.get(1), i.get(0));
                      if (abIdx == null) {
                        if (customVarianceSubstrings != null) {
                          for (String s : customVarianceSubstrings) {
                            if (i.get(4).contains(s)) {
                              basicVariance = true;
                              extendedVariance = true;
                            }
                          }
                        }
                        basicVariance = true;
                        if (considerSupporting(i.get(1))) {
                          extendedVariance = true;
                        }
                        continue;
                      }
                      Instant t = Instant.parse(i.get(3));
                      if (latestEpaRequest == null) {
                        latestEpaRequest = t;
                      } else if (t.getMillis() > latestEpaRequest.getMillis()) {
                        latestEpaRequest = t;
                      }
                      // XXX Just pick up the user agent here; with agent variance this could
                      // result in a different agent being included in the alert than the one
                      // that was actually associated with the threshold violation, and should
                      // be fixed.
                      userAgent = i.get(2);
                      endCounter[abIdx]++;
                    }

                    // If extended object variance is enabled, only consider variance if this
                    // flag has been set. Otherwise we by default consider basic variance to be
                    // enough.
                    if (varianceSupportingOnly) {
                      if (extendedVariance) {
                        return;
                      }
                    } else {
                      if (basicVariance) {
                        return;
                      }
                    }

                    // If we get here, there was not enough variance present, identify if any
                    // monitored endpoints have exceeded the threshold and use the one with
                    // the highest request count
                    Integer abmaxIndex = null;
                    int count = -1;
                    for (int i = 0; i < endpoints.length; i++) {
                      if (endpoints[i].threshold <= endCounter[i]) {
                        if (abmaxIndex == null) {
                          abmaxIndex = i;
                          count = endCounter[i];
                        } else {
                          if (count < endCounter[i]) {
                            abmaxIndex = i;
                            count = endCounter[i];
                          }
                        }
                      }
                    }

                    if (abmaxIndex == null) {
                      // No requests exceeded threshold
                      return;
                    }

                    log.info("{}: emitting alert for {} {}", w.toString(), remoteAddress, count);

                    String compareMethod = endpoints[abmaxIndex].method;
                    String comparePath = endpoints[abmaxIndex].path;

                    Alert a = new Alert();
                    a.setTimestamp(latestEpaRequest.toDateTime());
                    a.setSummary(
                        String.format(
                            "%s httprequest endpoint_abuse %s %s %s %d",
                            monitoredResource, remoteAddress, compareMethod, comparePath, count));
                    a.setCategory("httprequest");
                    a.setSubcategory("endpoint_abuse");
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
                    a.addMetadata(AlertMeta.Key.USERAGENT, userAgent);
                    a.setNotifyMergeKey(String.format("%s endpoint_abuse", monitoredResource));
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
        .apply("endpoint abuse analysis global", new GlobalTriggers<KV<String, Alert>>(5))
        .apply(ParDo.of(new AlertSuppressorCount(alertSuppressionDurationSeconds)));
  }

  private Boolean considerSupporting(String path) {
    if ((path.endsWith(".css"))
        || (path.endsWith(".js"))
        || (path.endsWith(".gif"))
        || (path.endsWith(".jpg"))
        || (path.endsWith(".ico"))
        || (path.endsWith(".svg"))
        || (path.endsWith(".png"))) {
      return true;
    }
    return false;
  }

  private Integer indexEndpoint(String path, String method) {
    for (int i = 0; i < endpoints.length; i++) {
      if ((endpoints[i].method.equals(method)) && (endpoints[i].path.equals(path))) {
        return i;
      }
    }
    return null;
  }
}
