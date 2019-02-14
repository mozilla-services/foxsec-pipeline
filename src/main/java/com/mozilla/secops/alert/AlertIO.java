package com.mozilla.secops.alert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.UUID;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.GlobalWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link AlertIO} provides an IO transform handling {@link Alert} output */
public class AlertIO {
  /**
   * Return {@link PTransform} to handle alerting output
   *
   * @return IO transform
   */
  public static Write write(AlertConfiguration cfg) {
    return new Write(cfg);
  }

  /**
   * Merge related alerts together using any set alert notify merge metadata prior to emitting
   * notifications.
   */
  public static class AlertNotifyMerge extends PTransform<PCollection<String>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<Alert> expand(PCollection<String> col) {
      return col.apply(
              Window.<String>into(new GlobalWindows())
                  .triggering(
                      Repeatedly.forever(
                          AfterProcessingTime.pastFirstElementInPane()
                              .plusDelayOf(Duration.standardMinutes(1))))
                  .discardingFiredPanes())
          .apply(
              "extract merge keys",
              ParDo.of(
                  new DoFn<String, KV<String, Alert>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Alert a = Alert.fromJSON(c.element());
                      if (a == null) {
                        return;
                      }
                      String key = a.getNotifyMergeKey();
                      if (key == null) {
                        key = UUID.randomUUID().toString();
                      }
                      c.output(KV.of(key, a));
                    }
                  }))
          .apply(GroupByKey.<String, Alert>create())
          .apply(
              "merge alerts",
              ParDo.of(
                  new DoFn<KV<String, Iterable<Alert>>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Iterable<Alert> alerts = c.element().getValue();
                      if (alerts == null) {
                        return;
                      }
                      ArrayList<Alert> alist = new ArrayList<>();
                      for (Alert a : alerts) {
                        alist.add(a);
                      }
                      if (alist.size() < 1) {
                        return;
                      } else if (alist.size() == 1) {
                        c.output(alist.get(0));
                        return;
                      }
                      Alert tosend = alist.get(0);
                      tosend.addMetadata("notify_merged_count", Integer.toString(alist.size()));

                      // Also include the number of merged alerts at the end of the summary being
                      // sent for the notification
                      tosend.setSummary(
                          tosend.getSummary()
                              + String.format(" (%d similar alerts)", alist.size() - 1));

                      c.output(tosend);
                    }
                  }));
    }
  }

  /**
   * Handle alerting output based on the contents of the alerting messages such as included metadata
   * and severity.
   */
  public static class Write extends PTransform<PCollection<String>, PDone> {
    private static final long serialVersionUID = 1L;
    private final AlertConfiguration cfg;

    /**
     * Get alert configuration in transform
     *
     * @return {@link AlertConfiguration}
     */
    public AlertConfiguration getAlertConfiguration() {
      return cfg;
    }

    /**
     * Create new alert handler transform
     *
     * @param cfg Alerting configuration
     */
    public Write(AlertConfiguration cfg) {
      this.cfg = cfg;
    }

    @Override
    public PDone expand(PCollection<String> input) {
      input.apply(new AlertNotifyMerge()).apply(ParDo.of(new WriteFn(this)));
      return PDone.in(input.getPipeline());
    }
  }

  private static class WriteFn extends DoFn<Alert, Void> {
    private static final long serialVersionUID = 1L;

    private final Write wTransform;
    private Logger log;

    private AlertConfiguration cfg;
    private AlertMailer mailer;
    private AlertSlack slack;

    public WriteFn(Write wTransform) {
      this.wTransform = wTransform;
      cfg = wTransform.getAlertConfiguration();
    }

    @Setup
    public void setup() throws IOException {
      log = LoggerFactory.getLogger(WriteFn.class);
      log.info("creating new alert output handler");

      if (cfg.getSmtpCredentials() != null) {
        log.info("configuration requires AlertMailer");
        mailer = new AlertMailer(cfg);
      }
      if (cfg.getSlackToken() != null) {
        log.info("configuration requires AlertSlack");
        slack = new AlertSlack(cfg);
      }
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      Alert a = c.element();
      String raw = a.toJSON();

      log.info("processing alert: {}", raw);

      if (!a.hasCorrectFields()) {
        log.warn("dropping incorrectly formatted alert: {}", raw);
        return;
      }

      if (mailer != null) {
        if (cfg.getEmailCatchall() != null) {
          // Configured catchall address always recieves a copy of the alert
          mailer.sendToCatchall(a);
        }

        // If a direct email metadata entry exists, also send the alert directly
        // to the specified address
        String sd = a.getMetadataValue("notify_email_direct");
        if (sd != null) {
          mailer.sendToAddress(a, sd);
        }
      }

      if (slack != null) {
        if (cfg.getSlackCatchall() != null) {
          // Configured catchall slack channel always recieves a copy of the alert
          if (!slack.sendToCatchall(a)) {
            log.error("failed to send alert to slack catchall");
          }
        }

        String slackEmail = a.getMetadataValue("notify_slack_direct");
        if (slackEmail != null) {
          if (!slack.sendToUser(a, slack.getUserId(slackEmail))) {
            log.error("failed to send notification via slack to user {}", slackEmail);
          }
        }
      }
    }
  }
}
