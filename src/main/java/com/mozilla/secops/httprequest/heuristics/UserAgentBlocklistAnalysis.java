package com.mozilla.secops.httprequest.heuristics;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.FileUtil;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.HTTPRequestMetrics.HeuristicMetrics;
import com.mozilla.secops.httprequest.HTTPRequestToggles;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Analysis to identify known bad user agents */
public class UserAgentBlocklistAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Boolean enableIprepdDatastoreExemptions;
  private final String iprepdDatastoreExemptionsProject;
  private final String uaBlocklistPath;

  private PCollectionView<Map<String, Boolean>> natView = null;
  private final HeuristicMetrics metrics;

  private Logger log;

  /**
   * Initialize new {@link UserAgentBlocklistAnalysis}
   *
   * @param toggles {@link HTTPRequestToggles}
   * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
   * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
   * @param natView Use {@link DetectNat} view, or null to disable
   */
  public UserAgentBlocklistAnalysis(
      HTTPRequestToggles toggles,
      Boolean enableIprepdDatastoreExemptions,
      String iprepdDatastoreExemptionsProject,
      PCollectionView<Map<String, Boolean>> natView) {
    monitoredResource = toggles.getMonitoredResource();
    this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
    this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
    this.natView = natView;
    uaBlocklistPath = toggles.getUserAgentBlocklistPath();
    log = LoggerFactory.getLogger(UserAgentBlocklistAnalysis.class);
    metrics = new HeuristicMetrics(UserAgentBlocklistAnalysis.class.getName());
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return new String(
        "Alert if client makes request with user agent that matches entry in blocklist.");
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> input) {
    if (natView == null) {
      // If natView was not set then we just create an empty view for use as the side input
      natView = DetectNat.getEmptyView(input.getPipeline());
    }
    return input
        .apply(
            "extract agent and source",
            ParDo.of(
                new DoFn<Event, KV<String, String>>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Normalized n = c.element().getNormalized();

                    String sourceAddress = n.getSourceAddress();
                    if (sourceAddress == null) {
                      return;
                    }

                    String ua = n.getUserAgent();
                    if (ua == null) {
                      return;
                    }
                    // As an optimization, anything resembling a Firefox user agent we will
                    // just exclude from further analysis in this transform.
                    if (ua.contains("Firefox/")) {
                      return;
                    }
                    c.output(KV.of(sourceAddress, ua));
                  }
                }))
        .apply("distinct agent and source", Distinct.<KV<String, String>>create())
        .apply(
            "isolate matching agents",
            ParDo.of(
                new DoFn<KV<String, String>, KV<String, String>>() {
                  private static final long serialVersionUID = 1L;

                  private Pattern uaRegex;

                  @Setup
                  public void setup() throws IOException {
                    ArrayList<String> in = FileUtil.fileReadLines(uaBlocklistPath);
                    uaRegex = Pattern.compile(String.join("|", in));
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    if (uaRegex.matcher(c.element().getValue()).matches()) {
                      c.output(c.element());
                    }
                  }
                }))
        .apply(GroupByKey.<String, String>create())
        .apply(
            "user agent blocklist analysis",
            ParDo.of(
                    new DoFn<KV<String, Iterable<String>>, Alert>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c, BoundedWindow w) {
                        Map<String, Boolean> nv = c.sideInput(natView);

                        String saddr = c.element().getKey();
                        // Iterable user agent list not currently used here, could probably be
                        // included in the alert metadata though.

                        Boolean isNat = nv.get(saddr);
                        if (isNat != null && isNat) {
                          log.info(
                              "{}: detectnat: skipping result emission for {}",
                              w.toString(),
                              saddr);
                          metrics.natDetected();
                          return;
                        }

                        Alert a = new Alert();
                        a.setSummary(
                            String.format(
                                "%s httprequest useragent_blocklist %s", monitoredResource, saddr));
                        a.setCategory("httprequest");
                        a.setSubcategory("useragent_blocklist");
                        a.addMetadata(AlertMeta.Key.SOURCEADDRESS, saddr);

                        try {
                          if (enableIprepdDatastoreExemptions) {
                            IprepdIO.addMetadataIfIpIsExempt(
                                saddr, a, iprepdDatastoreExemptionsProject);
                          }
                        } catch (IOException exc) {
                          log.error("error checking iprepd exemptions: {}", exc.getMessage());
                          return;
                        }

                        a.setNotifyMergeKey(
                            String.format("%s useragent_blocklist", monitoredResource));
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
}
