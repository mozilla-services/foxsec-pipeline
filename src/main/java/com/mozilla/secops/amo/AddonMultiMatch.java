package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.MiscUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/**
 * Detect distributed AMO submissions with the same file name
 *
 * <p>Detection operates on fixed windows of 10 minutes long. If the number of clients seen
 * uploading a file with the exact same file name exceeds the configured value within the fixed
 * window, an alert is generated.
 */
public class AddonMultiMatch extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer suppressRecovery;
  private final int matchAlertOn;

  /**
   * Construct new AddonMultiMatch
   *
   * @param monitoredResource Monitored resource indicator
   * @param suppressRecovery Optional recovery suppression to include with alerts in seconds
   * @param matchAlertOn Number of submissions of the same file name to trigger alert
   */
  public AddonMultiMatch(String monitoredResource, Integer suppressRecovery, Integer matchAlertOn) {
    this.monitoredResource = monitoredResource;
    this.suppressRecovery = suppressRecovery;
    this.matchAlertOn = matchAlertOn;
  }

  public String getTransformDoc() {
    return String.format(
        "Detect distributed AMO submissions with the same file name. Alert on %s submissions of the same file name.",
        matchAlertOn);
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "addon multi match fixed window",
            Window.<Event>into(FixedWindows.of(Duration.standardMinutes(10))))
        .apply(
            "addon multi match filter applicable",
            ParDo.of(
                new DoFn<Event, KV<String, String>>() {
                  private static final long serialVersionUID = 1L;

                  private final String fnRegexStr = "^[a-z0-9]{32}_(.*)$";
                  private Pattern fnRegex;

                  @Setup
                  public void setup() {
                    fnRegex = Pattern.compile(fnRegexStr);
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();
                    if (!e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                      return;
                    }
                    AmoDocker d = e.getPayload();
                    if ((d == null) || (d.getEventType() == null)) {
                      return;
                    }
                    if (!d.getEventType().equals(AmoDocker.EventType.FILEUPLOADMNT)) {
                      return;
                    }

                    // We want at least an email address and a file name
                    if ((d.getFxaEmail() == null) || (d.getFileName() == null)) {
                      return;
                    }

                    // Remove the prefix hash so we are left with the upload file name
                    Matcher mat = fnRegex.matcher(d.getFileName());
                    if (!mat.matches()) {
                      return;
                    }
                    String fncomp = mat.group(1);
                    if ((fncomp == null) || (fncomp.isEmpty())) {
                      return;
                    }
                    c.output(KV.of(fncomp, d.getFxaEmail()));
                  }
                }))
        .apply("addon multi match distinct", Distinct.<KV<String, String>>create())
        .apply("addon multi match gbk", GroupByKey.<String, String>create())
        .apply(
            "addon multi match analysis",
            ParDo.of(
                new DoFn<KV<String, Iterable<String>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    String buf = "";
                    int cnt = 0;

                    for (String s : c.element().getValue()) {
                      if (buf.isEmpty()) {
                        buf = s;
                      } else {
                        buf += ", " + s;
                      }
                      // When we are building the submission buffer, also include a normalized
                      // version of the address, and a dot normalized version
                      String nb = MiscUtil.normalizeEmailPlus(s);
                      if (!s.equals(nb)) {
                        buf += ", " + nb;
                      }
                      nb = MiscUtil.normalizeEmailPlusDotStrip(s);
                      if (!s.equals(nb)) {
                        buf += ", " + nb;
                      }
                      cnt++;
                    }
                    if (cnt < matchAlertOn) {
                      return;
                    }
                    Alert alert = new Alert();
                    alert.setCategory("amo");
                    alert.setSubcategory("amo_abuse_multi_match");
                    alert.setNotifyMergeKey("amo_abuse_multi_match");
                    alert.addMetadata("email", buf);
                    alert.addMetadata("count", Integer.toString(cnt));
                    alert.addMetadata("addon_filename", c.element().getKey());
                    alert.setSummary(
                        String.format("%s addon abuse multi match, %d", monitoredResource, cnt));
                    if (suppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(suppressRecovery, alert);
                    }
                    c.output(alert);
                  }
                }))
        .apply("addon multi match global triggers", new GlobalTriggers<Alert>(5));
  }
}
