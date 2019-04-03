package com.mozilla.secops.alert;

import com.mozilla.secops.crypto.RuntimeSecrets;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;
import javax.mail.Address;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link AlertMailer} handles SES based alerting output */
public class AlertMailer {
  private final AlertConfiguration cfg;
  private final Logger log;
  private final String smtpCreds;
  private TemplateManager templateManager;

  /**
   * Send email alert to specified address
   *
   * @param a Alert
   * @param address Recipient address
   */
  public void sendToAddress(Alert a, String address) {
    log.info("generating mail for {}", address);

    ArrayList<String> r = new ArrayList<String>();
    r.add(address);
    sendMail(r, a.getSummary(), a.assemblePayload(), createAlertMailBody(a));
  }

  /**
   * Send email alert to configured catchall address
   *
   * @param a Alert
   */
  public void sendToCatchall(Alert a) {
    String dest = cfg.getEmailCatchall();
    if (dest == null) {
      return;
    }
    log.info("generating catchall mail for {}", dest);

    ArrayList<String> r = new ArrayList<String>();
    r.add(dest);
    sendMail(r, a.getSummary(), a.assemblePayload(), createAlertMailBody(a));
  }

  private void sendMail(
      ArrayList<String> recipients, String subject, String textBody, String htmlBody) {
    String[] akeys = smtpCreds.split(":");
    if (akeys.length != 2) {
      log.error("mail submission failed: invalid SMTP credentials specified");
      return;
    }

    Properties props = new Properties();
    props.put("mail.smtp.auth", "true");
    props.put("mail.smtp.starttls.enable", "true");
    props.put("mail.smtp.host", cfg.getSmtpRelay());
    props.put("mail.smtp.port", "587");

    Session session =
        Session.getInstance(
            props,
            new Authenticator() {
              protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(akeys[0], akeys[1]);
              }
            });

    try {
      int asize = recipients.size();
      Address[] recips = new Address[asize];
      for (int i = 0; i < asize; i++) {
        recips[i] = new InternetAddress(recipients.get(i));
      }
      Message message = new MimeMessage(session);
      message.setFrom(new InternetAddress(cfg.getEmailFrom(), true));
      message.setRecipients(Message.RecipientType.TO, recips);
      message.setSubject(subject);
      message.setText(textBody);
      if (htmlBody != null) {
        message.setContent(htmlBody, "text/html; charset=utf-8");
      }
      Transport.send(message);
    } catch (MessagingException exc) {
      log.error("mail submission failed: {}", exc.getMessage());
    }
  }

  /**
   * Create new {@link AlertMailer} with specified {@link AlertConfiguration}
   *
   * @param cfg {@link AlertConfiguration}
   */
  public AlertMailer(AlertConfiguration cfg) {
    log = LoggerFactory.getLogger(AlertMailer.class);
    this.cfg = cfg;

    try {
      smtpCreds = RuntimeSecrets.interpretSecret(cfg.getSmtpCredentials(), cfg.getGcpProject());
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }

    templateManager = new TemplateManager(cfg);
  }

  private String createAlertMailBody(Alert a) {
    if (a.getEmailTemplateName() != null) {
      try {
        return templateManager.processTemplate(
            a.getEmailTemplateName(), a.generateTemplateVariables());
      } catch (Exception exc) {
        log.error("email body creation failed: {}", exc.getMessage());
      }
    }
    return null;
  }
}
