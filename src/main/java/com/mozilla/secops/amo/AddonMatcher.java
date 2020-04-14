package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.MiscUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/**
 * Match abusive addon uploads and generate alerts
 *
 * <p>Processes upload log messages that include information such as the upload file name and the
 * size of the upload. This is compared against configuration and if the criteria matches, an alert
 * will be generated of category amo_abuse_matched_addon.
 */
public class AddonMatcher extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer suppressRecovery;
  private final String[] matchCriteria;

  /**
   * Construct new AddonMatcher
   *
   * @param monitoredResource Monitored resource indicator
   * @param suppressRecovery Optional recovery suppression to include with alerts in seconds
   * @param matchCriteria Match criteria, filename_regex:minsizebytes:maxsizebytes
   */
  public AddonMatcher(String monitoredResource, Integer suppressRecovery, String[] matchCriteria) {
    this.monitoredResource = monitoredResource;
    this.suppressRecovery = suppressRecovery;
    this.matchCriteria = matchCriteria;
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return String.format(
        "Match abusive addon uploads using these patterns %s and generate alerts",
        Arrays.toString(matchCriteria));
  }

  private static class MatchCriteria {
    public Pattern pattern;
    public Integer minBytes;
    public Integer maxBytes;
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply("addon matcher global triggers", new GlobalTriggers<Event>(5))
        .apply(
            "addon matcher analysis",
            ParDo.of(
                new DoFn<Event, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private ArrayList<MatchCriteria> criteria;

                  @Setup
                  public void setup() {
                    criteria = new ArrayList<MatchCriteria>();
                    if (matchCriteria != null) {
                      for (String s : matchCriteria) {
                        String parts[] = s.split(":");
                        if (parts.length != 3) {
                          throw new IllegalArgumentException(
                              "invalid format for addon match criteria, must be <regex>:<minbytes>:<maxbytes>");
                        }
                        MatchCriteria c = new MatchCriteria();
                        c.pattern = Pattern.compile(parts[0]);
                        c.minBytes = new Integer(parts[1]);
                        c.maxBytes = new Integer(parts[2]);
                        criteria.add(c);
                      }
                    }
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

                    for (MatchCriteria crit : criteria) {
                      Matcher m = crit.pattern.matcher(d.getFileName());
                      if (m.matches()) {
                        if ((d.getBytes() < crit.minBytes) || (d.getBytes() > crit.maxBytes)) {
                          continue;
                        }
                        Alert alert = new Alert();
                        alert.setCategory("amo");
                        alert.setSubcategory("amo_abuse_matched_addon");
                        alert.setNotifyMergeKey("amo_abuse_matched_addon");
                        alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, d.getRemoteIp());
                        // If we got an email address with the event, add it to the alert; we also
                        // add the normalized email equivalents
                        if (d.getFxaEmail() != null) {
                          String email = d.getFxaEmail();
                          String buf = email;
                          String nb = MiscUtil.normalizeEmailPlus(email);
                          if (!email.equals(nb)) {
                            buf += ", " + nb;
                          }
                          nb = MiscUtil.normalizeEmailPlusDotStrip(email);
                          if (!email.equals(nb)) {
                            buf += ", " + nb;
                          }
                          alert.addMetadata(AlertMeta.Key.EMAIL, buf);
                        }
                        alert.addMetadata(AlertMeta.Key.ADDON_FILENAME, d.getFileName());
                        alert.addMetadata(AlertMeta.Key.ADDON_SIZE, d.getBytes().toString());
                        String summary =
                            String.format(
                                "%s suspected malicious addon submission from %s",
                                monitoredResource, d.getRemoteIp());
                        if (d.getFxaEmail() != null) {
                          summary = summary + ", " + d.getFxaEmail();
                        }
                        alert.setSummary(summary);
                        if (suppressRecovery != null) {
                          IprepdIO.addMetadataSuppressRecovery(suppressRecovery, alert);
                        }
                        c.output(alert);
                        return;
                      }
                    }
                  }
                }));
  }
}
