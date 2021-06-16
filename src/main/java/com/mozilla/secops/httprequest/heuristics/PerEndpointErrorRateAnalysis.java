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
import java.util.Arrays;
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
 * Transform for detection of a single source generating errors at a given path pattern. The path is
 * specified using a regex and an alert is generated if there are more than the threshold amount of
 * requests matching the path with a status in the 400's.
 *
 * <p>Generates alerts where the request profile violates path thresholds specified in the
 * perEndpointErrorRate pipeline option configuration.
 */
public class PerEndpointErrorRateAnalysis
    extends PTransform<PCollection<KV<String, ArrayList<String>>>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private Logger log;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;
  private final PerEndpointErrorRateAnalysis.EndpointErrorInfo[] endpointInfo;
  private final Integer suppressRecovery;
  private final Long sessionGapDurationMinutes;
  private final Long alertSuppressionDurationSeconds;

  /**
   * Initializer for {@link PerEndpointErrorRateAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   */
  public PerEndpointErrorRateAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject) {
    log = LoggerFactory.getLogger(PerEndpointErrorRateAnalysis.class);

    this.monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    this.suppressRecovery = toggles.getPerEndpointErrorRateSuppressRecovery();
    this.sessionGapDurationMinutes = toggles.getErrorSessionGapDurationMinutes();
    this.alertSuppressionDurationSeconds =
        toggles.getPerEndpointErrorRateAlertSuppressionDurationSeconds();

    String[] cfgEndpoints = toggles.getPerEndpointErrorRatePaths();

    this.endpointInfo = new PerEndpointErrorRateAnalysis.EndpointErrorInfo[cfgEndpoints.length];

    for (int i = 0; i < cfgEndpoints.length; i++) {
      String[] parts = cfgEndpoints[i].split(":");
      if (parts.length != 3) {
        throw new IllegalArgumentException(
            "invalid format for per endpoint error rate analysis, must be <int>:<method>:<path>");
      }
      PerEndpointErrorRateAnalysis.EndpointErrorInfo ninfo = new EndpointErrorInfo();
      ninfo.threshold = Integer.parseInt(parts[0]);
      ninfo.method = parts[1];
      ninfo.path = Pattern.compile(parts[2]);

      endpointInfo[i] = ninfo;
    }
  }

  /** Internal class for configured endpoints in PEERA */
  public static class EndpointErrorInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Request method */
    public String method;

    /** Path (pattern) */
    public Pattern path;

    /** Threshold */
    public Integer threshold;

    /** Interval */
    public Long interval;

    /** Returns true if an event matches the endpoint for both method and path */
    boolean matchesEvent(String eventMethod, String eventPath) {
      return method.equals(eventMethod) && path.matcher(eventPath).matches();
    }
  }

  /** Internal class to keep track of current state for a given endpoint rule for this key */
  public static class EndpointErrorState implements Serializable {
    private static final long serialVersionUID = 1L;
    int errorCounter;
    Instant mostRecentError;
    String userAgent;

    /**
     * Increments the counter and if this is the most recent event seen update the timestamp and use
     * this event's useragent for any alerts generated
     */
    void update(Instant timestamp, String userAgent) {
      errorCounter++;
      if (mostRecentError == null || mostRecentError.isBefore(timestamp)) {
        mostRecentError = timestamp;
        this.userAgent = userAgent;
      }
    }
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    String buf = null;
    for (int i = 0; i < endpointInfo.length; i++) {
      String x =
          String.format(
              "%d errors to endpoints matching %s %s.",
              endpointInfo[i].threshold, endpointInfo[i].method, endpointInfo[i].path);
      if (buf == null) {
        buf = x;
      } else {
        buf += " " + x;
      }
    }
    return String.format(
        "Clients are sessionized by address, where a session ends after "
            + "%d minutes of inactivity. An alert is generated if a client is observed "
            + "making repeated requests to configured endpoints that result in higher "
            + "amount of errors. %s",
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
                    Iterable<ArrayList<String>> errors = c.element().getValue();
                    PerEndpointErrorRateAnalysis.EndpointErrorState[] state =
                        new PerEndpointErrorRateAnalysis.EndpointErrorState[endpointInfo.length];
                    Arrays.setAll(state, i -> new EndpointErrorState());

                    for (ArrayList<String> e : errors) {
                      String method = e.get(0);
                      String path = e.get(1);
                      for (int i = 0; i < endpointInfo.length; i++) {
                        if (endpointInfo[i].matchesEvent(method, path)) {
                          Instant ts = Instant.parse(e.get(3));
                          String userAgent = e.get(2);
                          state[i].update(ts, userAgent);
                        }
                      }
                    }

                    // find the endpoint with the highest count and use that to
                    // generate alert
                    Integer max = null;
                    int count = -1;
                    for (int i = 0; i < endpointInfo.length; i++) {
                      if (endpointInfo[i].threshold <= state[i].errorCounter) {
                        if (max == null) {
                          max = i;
                          count = state[i].errorCounter;
                        } else {
                          if (count < state[i].errorCounter) {
                            max = i;
                            count = state[i].errorCounter;
                          }
                        }
                      }
                    }

                    if (max == null) {
                      return;
                    }

                    Alert a = new Alert();
                    a.setTimestamp(state[max].mostRecentError.toDateTime());
                    a.setSummary(
                        String.format(
                            "%s httprequest per_endpoint_error_rate %s %s %s %d",
                            monitoredResource,
                            remoteAddress,
                            endpointInfo[max].method,
                            endpointInfo[max].path.pattern(),
                            state[max].errorCounter));
                    a.setCategory("httprequest");
                    a.setSubcategory("per_endpoint_error_rate");
                    a.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);

                    if (enableIprepdDatastoreExemptions) {
                      try {
                        IprepdIO.addMetadataIfIpIsExempt(
                            remoteAddress, a, iprepdDatastoreExemptionsProject);
                      } catch (IOException exc) {
                        log.error("error checking iprepd exemptions: {}", exc.getMessage());
                        return;
                      }
                    }
                    if (suppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(suppressRecovery, a);
                    }
                    a.addMetadata(AlertMeta.Key.COUNT, String.valueOf(state[max].errorCounter));
                    a.addMetadata(
                        AlertMeta.Key.ENDPOINT_PATTERN, endpointInfo[max].path.toString());
                    a.addMetadata(
                        AlertMeta.Key.ERROR_THRESHOLD, String.valueOf(endpointInfo[max].threshold));
                    a.setNotifyMergeKey(
                        String.format("%s per_endpoint_error_rate", monitoredResource));
                    a.addMetadata(
                        AlertMeta.Key.WINDOW_TIMESTAMP,
                        (new DateTime(w.maxTimestamp())).toString());
                    if (!a.hasCorrectFields()) {
                      throw new IllegalArgumentException("alert has invalid field configuration");
                    }
                    c.output(KV.of(remoteAddress, a));
                  }
                }))
        .apply("per endpoint error analysis global", new GlobalTriggers<KV<String, Alert>>(5))
        .apply(ParDo.of(new AlertSuppressorCount(alertSuppressionDurationSeconds)));
  }
}
