package com.mozilla.secops.httprequest.heuristics;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.HTTPRequestMetrics.HeuristicMetrics;
import com.mozilla.secops.httprequest.HTTPRequestToggles;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transform for detection of a single source making a sequence of requests at a speed faster than
 * what we expect from a normal user.
 *
 * <p>Generates alerts where the request profile violates path thresholds specified in the
 * endpointAbusePath pipeline option configuration.
 */
public class EndpointSequenceAbuse extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private Logger log;

  private final EndpointSequenceAbuse.EndpointSequenceAbuseTimingInfo[] endpointPatterns;
  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;
  private final Integer suppressRecovery;
  private PCollectionView<Map<String, Boolean>> natView = null;
  private final HeuristicMetrics metrics;

  /** Internal class for configured endpoints in EPA */
  public static class EndpointSequenceAbuseTimingInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    public Integer threshold;

    public String firstMethod;
    public String firstPath;

    public Integer deltaMs;

    public String secondMethod;
    public String secondPath;

    /**
     * Convert configuration to String
     *
     * @return Class parameters as a string
     */
    public String toString() {
      return String.format(
          "%d:%s:%s:%d:%s:%s",
          threshold, firstMethod, firstPath, deltaMs, secondMethod, secondPath);
    }
  }

  /**
   * Static initializer for {@link EndpointAbuseAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   * @param natView Use {@link DetectNat} view, or null to disable
   */
  public EndpointSequenceAbuse(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject,
      PCollectionView<Map<String, Boolean>> natView) {
    log = LoggerFactory.getLogger(EndpointSequenceAbuse.class);
    monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    suppressRecovery = toggles.getEndpointSequenceAbuseSuppressRecovery();
    this.natView = natView;
    metrics = new HeuristicMetrics(EndpointSequenceAbuse.class.getName());

    String[] cfgEndpoints = toggles.getEndpointSequenceAbusePatterns();
    endpointPatterns =
        new EndpointSequenceAbuse.EndpointSequenceAbuseTimingInfo[cfgEndpoints.length];
    for (int i = 0; i < cfgEndpoints.length; i++) {
      String[] parts = cfgEndpoints[i].split(":");
      if (parts.length != 6) {
        throw new IllegalArgumentException(
            "invalid format for abuse endpoint timing, must be <int>:<method>:<path>:<int>:<method>:<path>");
      }
      EndpointSequenceAbuse.EndpointSequenceAbuseTimingInfo ninfo =
          new EndpointSequenceAbuseTimingInfo();
      ninfo.threshold = Integer.parseInt(parts[0]);
      ninfo.firstMethod = parts[1];
      ninfo.firstPath = parts[2];
      ninfo.deltaMs = Integer.parseInt(parts[3]);
      ninfo.secondMethod = parts[4];
      ninfo.secondPath = parts[5];
      endpointPatterns[i] = ninfo;
    }
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    String buf = null;
    for (int i = 0; i < endpointPatterns.length; i++) {
      String x =
          String.format(
              "%d %s %s requests within %d ms of last %s %s request.",
              endpointPatterns[i].threshold,
              endpointPatterns[i].secondMethod,
              endpointPatterns[i].secondPath,
              endpointPatterns[i].deltaMs,
              endpointPatterns[i].firstMethod,
              endpointPatterns[i].firstPath);
      if (buf == null) {
        buf = x;
      } else {
        buf += " " + x;
      }
    }
    return String.format(
        "An alert is generated when a client (identified by ip) makes requests for a sequence of endpoints within a configurable delta thought to be atypical of a normal user. %s",
        buf);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> input) {
    if (natView == null) {
      // If natView was not set then we just create an empty view for use as the side input
      natView = DetectNat.getEmptyView(input.getPipeline());
    }
    return input
        .apply(
            "filter events and key by ip",
            ParDo.of(
                new DoFn<Event, KV<String, Event>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c, BoundedWindow w) {
                    Event event = c.element();
                    Normalized n = event.getNormalized();
                    String sourceAddress = n.getSourceAddress();
                    String method = n.getRequestMethod();
                    String path = n.getUrlRequestPath();
                    if (sourceAddress == null || method == null || path == null) {
                      return;
                    }
                    // only output events if they belong to one of our sequences
                    if (belongsToSequence(method, path)) {
                      c.output(KV.of(sourceAddress, event));
                    }
                  }
                }))
        .apply(GroupByKey.<String, Event>create())
        .apply(
            "analyze per-client",
            ParDo.of(
                    new DoFn<KV<String, Iterable<Event>>, Alert>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c, BoundedWindow w) {
                        String remoteAddress = c.element().getKey();
                        Iterable<Event> events = c.element().getValue();

                        // sort events by timestamp
                        List<Event> eventList =
                            StreamSupport.stream(events.spliterator(), false)
                                .sorted((e1, e2) -> e1.getTimestamp().compareTo(e2.getTimestamp()))
                                .collect(Collectors.toList());

                        int[] violationsCounter = new int[endpointPatterns.length];
                        Instant[] lastViolationTimestamp = new Instant[endpointPatterns.length];
                        String[] lastViolationUserAgent = new String[endpointPatterns.length];

                        // used to track last time we saw the first part of each
                        // request sequence used for timing analysis
                        Instant[] lastFirstRequest = new Instant[endpointPatterns.length];

                        // for each path
                        for (Event event : eventList) {
                          Normalized n = event.getNormalized();

                          // check if its a first item in an endpoint sequence
                          ArrayList<Integer> indices =
                              findFirstHalfPatternMatches(
                                  n.getRequestMethod(), n.getUrlRequestPath());

                          // for any sequence its a part of update the latest timestamp for it
                          for (Integer m : indices) {
                            lastFirstRequest[m] = Instant.parse(event.getTimestamp().toString());
                          }

                          // check if its a second item in an endpoint sequence
                          ArrayList<Integer> secondIndices =
                              findSecondHalfPatternMatches(
                                  n.getRequestMethod(), n.getUrlRequestPath());

                          // for any sequence its the second part of, check the delta and increase
                          // count if it is
                          for (Integer m : secondIndices) {
                            Instant ts = Instant.parse(event.getTimestamp().toString());
                            if (lastFirstRequest[m] != null) {
                              if (ts.isBefore(
                                  lastFirstRequest[m].plus(endpointPatterns[m].deltaMs))) {
                                lastViolationUserAgent[m] =
                                    n.getUserAgent() == null ? "" : n.getUserAgent();
                                lastViolationTimestamp[m] = ts;
                                violationsCounter[m]++;
                              }
                            }
                          }
                        }

                        // identify if any monitored endpoints have
                        // exceeded the threshold and use the one with
                        // the highest count
                        Integer abmaxIndex = null;
                        int count = -1;
                        for (int i = 0; i < endpointPatterns.length; i++) {
                          if (endpointPatterns[i].threshold <= violationsCounter[i]) {
                            if (abmaxIndex == null) {
                              abmaxIndex = i;
                              count = violationsCounter[i];
                            } else {
                              if (count < violationsCounter[i]) {
                                abmaxIndex = i;
                                count = violationsCounter[i];
                              }
                            }
                          }
                        }

                        if (abmaxIndex == null) {
                          // No requests exceeded threshold
                          return;
                        }

                        Map<String, Boolean> nv = c.sideInput(natView);
                        Boolean isNat = nv.get(remoteAddress);
                        if (isNat != null && isNat) {
                          log.info(
                              "{}: detectnat: skipping result emission for {}",
                              w.toString(),
                              remoteAddress);
                          metrics.natDetected();
                          return;
                        }

                        log.info(
                            "{}: emitting alert for {} {}", w.toString(), remoteAddress, count);

                        String compareFirstMethod = endpointPatterns[abmaxIndex].firstMethod;
                        String compareFirstPath = endpointPatterns[abmaxIndex].firstPath;

                        Integer compareDelta = endpointPatterns[abmaxIndex].deltaMs;

                        String compareSecondMethod = endpointPatterns[abmaxIndex].secondMethod;
                        String compareSecondPath = endpointPatterns[abmaxIndex].secondPath;

                        Alert a = new Alert();
                        a.setTimestamp(lastViolationTimestamp[abmaxIndex].toDateTime());
                        a.setSummary(
                            String.format(
                                "%s httprequest endpoint_sequence_abuse %s %s:%s:%d:%s:%s %d",
                                monitoredResource,
                                remoteAddress,
                                compareFirstMethod,
                                compareFirstPath,
                                compareDelta,
                                compareSecondMethod,
                                compareSecondPath,
                                count));
                        a.setCategory("httprequest");
                        a.setSubcategory("endpoint_sequence_abuse");
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

                        a.addMetadata(
                            AlertMeta.Key.ENDPOINT_PATTERN,
                            endpointPatterns[abmaxIndex].toString());
                        a.addMetadata(AlertMeta.Key.COUNT, Integer.toString(count));
                        a.addMetadata(AlertMeta.Key.USERAGENT, lastViolationUserAgent[abmaxIndex]);
                        a.setNotifyMergeKey(
                            String.format("%s endpoint_sequence_abuse", monitoredResource));
                        a.addMetadata(
                            AlertMeta.Key.WINDOW_TIMESTAMP,
                            (new DateTime(w.maxTimestamp())).toString());
                        if (!a.hasCorrectFields()) {
                          throw new IllegalArgumentException(
                              "alert has invalid field configuration");
                        }
                        c.output(a);
                      }
                    })
                .withSideInputs(natView));
  }

  /**
   * Returns the indices of the endpoint sequences that the given method/path match the first part
   * of the pattern
   */
  private ArrayList<Integer> findFirstHalfPatternMatches(String method, String path) {
    ArrayList<Integer> indices = new ArrayList<Integer>();
    for (int i = 0; i < endpointPatterns.length; i++) {
      if ((endpointPatterns[i].firstMethod.equals(method))
          && (endpointPatterns[i].firstPath.equals(path))) {
        indices.add(i);
      }
    }
    return indices;
  }

  /**
   * Returns the indices of the endpoint sequences that the given method/path match the second part
   * of the pattern
   */
  private ArrayList<Integer> findSecondHalfPatternMatches(String method, String path) {
    ArrayList<Integer> indices = new ArrayList<Integer>();
    for (int i = 0; i < endpointPatterns.length; i++) {
      if ((endpointPatterns[i].secondMethod.equals(method))
          && (endpointPatterns[i].secondPath.equals(path))) {
        indices.add(i);
      }
    }
    return indices;
  }

  /**
   * Returns true if the method/path combination is part of any sequence (regardless of position)
   */
  private Boolean belongsToSequence(String method, String path) {
    return !(findFirstHalfPatternMatches(method, path).isEmpty()
        && findSecondHalfPatternMatches(method, path).isEmpty());
  }
}
