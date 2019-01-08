package com.mozilla.secops.alert;

import java.io.IOException;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;
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
      input.apply(ParDo.of(new WriteFn(this)));
      return PDone.in(input.getPipeline());
    }
  }

  private static class WriteFn extends DoFn<String, Void> {
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
      String raw = c.element();
      Alert a = Alert.fromJSON(raw);
      if (a == null) {
        return;
      }
      log.info("processing alert: {}", raw);

      if (mailer != null) {
        if (cfg.getEmailCatchall() != null) {
          // Configured catchall address always recieves a copy of the alert
          mailer.sendToCatchall(a);
        }

        String sd = a.getMetadataValue("notify_email_direct");
        if (sd != null) {
          mailer.sendToAddress(a, sd);
        }
      }

      if (slack != null) {
        String slackEmail = a.getMetadataValue("notify_slack_direct");
        if (slackEmail != null) {
          try {
            slack.confirmationAlert(a, slack.getUserId(slackEmail));
          } catch (Exception exc) {
            log.error("error sending slack alert: {}", exc.getMessage());
          }
        }
      }
    }
  }
}
