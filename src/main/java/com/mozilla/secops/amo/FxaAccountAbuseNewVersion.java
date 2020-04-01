package com.mozilla.secops.amo;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.AmoDocker;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * Correlation of AMO addon submission with abusive FxA account creation alerts
 *
 * <p>This transform also applies login ban patterns.
 */
public class FxaAccountAbuseNewVersion extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String monitoredResource;
  private final String iprepdSpec;
  private final String project;
  private final String[] banAccounts;
  private final Integer banAccountsSuppress;

  /**
   * Create new FxaAccountAbuseNewVersion
   *
   * @param monitoredResource Monitored resource indicator
   * @param banAccounts Blacklisted accounts regex
   * @param banAccountsSuppress Optional recovery suppression for ban pattern alerts
   * @param iprepdSpec iprepd spec for reputation lookups
   * @param project Project for KMS secrets decryption of API key if required
   */
  public FxaAccountAbuseNewVersion(
      String monitoredResource,
      String[] banAccounts,
      Integer banAccountsSuppress,
      String iprepdSpec,
      String project) {
    this.monitoredResource = monitoredResource;

    this.banAccounts = banAccounts;
    this.banAccountsSuppress = banAccountsSuppress;

    this.iprepdSpec = iprepdSpec;
    this.project = project;
  }

  /** Transform documentation for users - see {@link com.mozilla.secops.DocumentingTransform} */
  public String getTransformDoc() {
    return String.format(
        "Correlates AMO addon submissions with abusive FxA account creation alerts via iprepd. Also includes blacklisted accounts regex: %s",
        Arrays.toString(banAccounts));
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    PCollection<Event> wEvents =
        col.apply("fxa account abuse new version window", new GlobalTriggers<Event>(5))
            .apply(
                "fxa account abuse new version filter applicable",
                ParDo.of(
                    new DoFn<Event, Event>() {
                      private static final long serialVersionUID = 1L;

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
                        if ((d.getEventType().equals(AmoDocker.EventType.NEWVERSION))
                            || (d.getEventType().equals(AmoDocker.EventType.FILEUPLOAD))
                            || (d.getEventType().equals(AmoDocker.EventType.GOTPROFILE))) {
                          c.output(e);
                          return;
                        }
                      }
                    }));

    PCollectionList<Alert> alerts = PCollectionList.empty(col.getPipeline());

    alerts =
        alerts.and(
            wEvents.apply(
                "fxa account abuse ban patterns",
                ParDo.of(
                    new DoFn<Event, Alert>() {
                      private static final long serialVersionUID = 1L;

                      private ArrayList<Pattern> banAccountsPat;

                      @Setup
                      public void setup() {
                        banAccountsPat = new ArrayList<Pattern>();
                        if (banAccounts != null) {
                          for (String x : banAccounts) {
                            banAccountsPat.add(Pattern.compile(x));
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
                        if (!d.getEventType().equals(AmoDocker.EventType.GOTPROFILE)) {
                          return;
                        }

                        // Compare profile against configured ban patterns
                        boolean configuredBan = false;
                        for (Pattern p : banAccountsPat) {
                          if (p.matcher(d.getFxaEmail()).matches()) {
                            configuredBan = true;
                            break;
                          }
                        }

                        if (configuredBan) {
                          Alert alert = new Alert();
                          alert.setCategory("amo");
                          alert.setSubcategory("fxa_account_abuse_new_version_login_banpattern");
                          alert.setNotifyMergeKey("fxa_account_abuse_new_version_login_banpattern");
                          alert.addMetadata("sourceaddress", d.getRemoteIp());
                          alert.addMetadata("email", d.getFxaEmail());
                          alert.setSummary(
                              String.format(
                                  "%s login to amo from suspected fraudulent account, %s from %s",
                                  monitoredResource, d.getFxaEmail(), d.getRemoteIp()));
                          if (banAccountsSuppress != null) {
                            IprepdIO.addMetadataSuppressRecovery(banAccountsSuppress, alert);
                          }
                          c.output(alert);
                          return;
                        }
                      }
                    })));

    alerts =
        alerts.and(
            wEvents.apply(
                "fxa account abuse new version",
                ParDo.of(
                    new DoFn<Event, Alert>() {
                      private static final long serialVersionUID = 1L;

                      private IprepdIO.Reader iprepdReader;

                      @Setup
                      public void setup() {
                        iprepdReader = IprepdIO.getReader(iprepdSpec, project);
                      }

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        Event e = c.element();

                        if (!e.getPayloadType().equals(Payload.PayloadType.AMODOCKER)) {
                          return;
                        }

                        AmoDocker d = e.getPayload();
                        if (d.getEventType().equals(AmoDocker.EventType.GOTPROFILE)) {
                          // This was a profile fetch, compare the email account against stored
                          // account reputation information.
                          Integer rep = iprepdReader.getReputation("email", d.getFxaEmail());

                          if (rep <= 50) {
                            Alert alert = new Alert();
                            alert.setCategory("amo");
                            alert.setNotifyMergeKey("fxa_account_abuse_new_version_login");
                            alert.addMetadata("sourceaddress", d.getRemoteIp());
                            alert.addMetadata("email", d.getFxaEmail());
                            alert.addMetadata(
                                "amo_category", "fxa_account_abuse_new_version_login");
                            alert.setSummary(
                                String.format(
                                    "%s login to amo from suspected fraudulent account, %s from %s",
                                    monitoredResource, d.getFxaEmail(), d.getRemoteIp()));
                            c.output(alert);
                            return;
                          }
                        } else if ((d.getEventType().equals(AmoDocker.EventType.NEWVERSION))
                            || (d.getEventType().equals(AmoDocker.EventType.FILEUPLOAD))) {
                          Integer rep = iprepdReader.getReputation("ip", d.getRemoteIp());
                          if (rep > 50) {
                            return;
                          }
                          // Address had a sufficiently low reputation score
                          Alert alert = new Alert();
                          alert.setCategory("amo");
                          alert.setNotifyMergeKey("fxa_account_abuse_new_version_submission");
                          alert.addMetadata("sourceaddress", d.getRemoteIp());
                          alert.addMetadata(
                              "amo_category", "fxa_account_abuse_new_version_submission");
                          if (d.getAddonId() != null) {
                            alert.addMetadata("addon_id", d.getAddonId());
                          }
                          if (d.getAddonVersion() != null) {
                            alert.addMetadata("addon_version", d.getAddonVersion());
                          }
                          alert.setSummary(
                              String.format(
                                  "%s addon submission from address associated with suspected "
                                      + "fraudulent account, %s",
                                  monitoredResource, d.getRemoteIp()));
                          c.output(alert);
                        }
                      }
                    })));

    return alerts.apply("flatten fxa account abuse", Flatten.<Alert>pCollections());
  }
}
