package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.MiscUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Sessions;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Multiple account logins for the same account from different source addresses associated with
 * different country codes
 *
 * <p>The analysis is based on sessions with a 15 minute gap duration.
 */
public class AddonMultiIpLogin extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final Integer suppressRecovery;
  private final Integer alertOn;
  private final Integer alertOnIp;
  private final String[] acctExceptions;
  private final String[] aggMatchers;

  /**
   * Construct new AddonMultiIpLogin
   *
   * @param monitoredResource Monitored resource indicator
   * @param suppressRecovery Optional recovery suppression to include with alerts in seconds
   * @param alertOn The number of different countries that must be seen for an alert to fire
   * @param alertOnIp If country count exceeded, IP count for the user must also exceed value
   * @param acctExceptions Array containing regex for account exceptions
   * @param aggMatchers Aggressive violation account matchers
   */
  public AddonMultiIpLogin(
      String monitoredResource,
      Integer suppressRecovery,
      Integer alertOn,
      Integer alertOnIp,
      String[] acctExceptions,
      String[] aggMatchers) {
    this.monitoredResource = monitoredResource;
    this.suppressRecovery = suppressRecovery;
    this.alertOn = alertOn;
    this.alertOnIp = alertOnIp;
    this.acctExceptions = acctExceptions;
    this.aggMatchers = aggMatchers;
  }

  /** Transform documentation for users - see {@link com.mozilla.secops.DocumentingTransform} */
  public String getTransformDoc() {
    return String.format(
        "Detect multiple account logins for the same account from different source addresses associated with different country codes. Alert on %s different countries and %s different IPs. Regex for account exceptions: %s",
        alertOn, alertOnIp, Arrays.toString(acctExceptions));
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "addon multi ip login filter applicable",
            ParDo.of(
                new DoFn<Event, KV<String, String>>() {
                  private static final long serialVersionUID = 1L;

                  private ArrayList<Pattern> exceptRe;

                  @Setup
                  public void setup() {
                    exceptRe = new ArrayList<Pattern>();
                    if (acctExceptions != null) {
                      for (String i : acctExceptions) {
                        exceptRe.add(Pattern.compile(i));
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
                    if ((!d.getEventType().equals(AmoDocker.EventType.LOGIN))
                        && (!d.getEventType().equals(AmoDocker.EventType.FILEUPLOADMNT))) {
                      return;
                    }

                    // We want an email address, remote address, and a source country code
                    if ((d.getFxaEmail() == null)
                        || (d.getRemoteIp() == null)
                        || (d.getSourceAddressCountry() == null)) {
                      return;
                    }

                    // Filter certain accounts
                    for (Pattern i : exceptRe) {
                      Matcher m = i.matcher(d.getFxaEmail());
                      if (m.matches()) {
                        return;
                      }
                    }

                    String buf = "login";
                    if (d.getEventType().equals(AmoDocker.EventType.FILEUPLOADMNT)) {
                      buf = "upload";
                    }

                    c.output(
                        KV.of(
                            d.getFxaEmail(),
                            d.getRemoteIp() + "|" + d.getSourceAddressCountry() + "|" + buf));
                  }
                }))
        .apply(
            "addon multi ip login session window",
            Window.<KV<String, String>>into(Sessions.withGapDuration(Duration.standardMinutes(15)))
                .triggering(
                    Repeatedly.forever(
                        AfterWatermark.pastEndOfWindow()
                            .withEarlyFirings(
                                AfterProcessingTime.pastFirstElementInPane()
                                    .plusDelayOf(Duration.standardSeconds(60)))))
                .withAllowedLateness(Duration.ZERO)
                .accumulatingFiredPanes())
        .apply("addon multi ip login gbk", GroupByKey.<String, String>create())
        .apply(
            "addon multi ip login analysis",
            ParDo.of(
                new DoFn<KV<String, Iterable<String>>, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private Logger log;
                  private ArrayList<Pattern> aggRe;

                  @Setup
                  public void setup() {
                    log = LoggerFactory.getLogger(AddonMultiIpLogin.class);

                    aggRe = new ArrayList<Pattern>();
                    if (aggMatchers != null) {
                      for (String i : aggMatchers) {
                        aggRe.add(Pattern.compile(i));
                      }
                    }
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    ArrayList<String> mCont = new ArrayList<>();
                    ArrayList<String> mIp = new ArrayList<>();

                    int lcnt = 0;
                    int ucnt = 0;

                    String logbuf = "";
                    for (String s : c.element().getValue()) {
                      String[] parts = s.split("\\|");
                      if (parts.length != 3) {
                        return;
                      }
                      if (parts[2].equals("upload")) {
                        ucnt++;
                      } else {
                        lcnt++;
                      }
                      if (!mIp.contains(parts[0])) {
                        mIp.add(parts[0]);
                      }
                      if (!mCont.contains(parts[1])) {
                        mCont.add(parts[1]);
                        if (logbuf.isEmpty()) {
                          logbuf = parts[1];
                        } else {
                          logbuf += "," + parts[1];
                        }
                      }
                    }
                    log.info(
                        "analyze {} {} {}, {} login {} upload",
                        c.element().getKey(),
                        logbuf,
                        mIp.size(),
                        lcnt,
                        ucnt);

                    if (mCont.size() < alertOn) {
                      return;
                    }

                    boolean aggMatch = false;
                    for (Pattern i : aggRe) {
                      Matcher m = i.matcher(c.element().getKey());
                      if (m.matches()) {
                        aggMatch = true;
                        break;
                      }
                    }

                    // If it did not match the aggressive match list, also check the IP count
                    if (!aggMatch) {
                      if (mIp.size() < alertOnIp) {
                        return;
                      }
                    }

                    String email = c.element().getKey();
                    String buf = email;
                    String nb = MiscUtil.normalizeEmailPlus(email);
                    if (!email.equals(nb)) {
                      buf += ", " + nb;
                    }
                    nb = MiscUtil.normalizeEmailPlusDotStrip(email);
                    if (!email.equals(nb)) {
                      buf += ", " + nb;
                    }

                    Alert alert = new Alert();
                    alert.setCategory("amo");
                    alert.setSubcategory("amo_abuse_multi_ip_login");
                    alert.setNotifyMergeKey("amo_abuse_multi_ip_login");
                    alert.addMetadata("email", buf);
                    alert.addMetadata("count", Integer.toString(mCont.size()));
                    alert.setSummary(
                        String.format(
                            "%s addon abuse multi ip country login, %s %d countries, %d source address",
                            monitoredResource, c.element().getKey(), mCont.size(), mIp.size()));
                    if (suppressRecovery != null) {
                      IprepdIO.addMetadataSuppressRecovery(suppressRecovery, alert);
                    }
                    c.output(alert);
                  }
                }))
        .apply("addon multi ip login global triggers", new GlobalTriggers<Alert>(5));
  }
}
