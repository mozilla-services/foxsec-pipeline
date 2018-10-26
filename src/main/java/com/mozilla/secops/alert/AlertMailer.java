package com.mozilla.secops.alert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.crypto.RuntimeSecrets;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.MessagingException;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

/**
 * {@link AlertMailer} handles SES based alerting output
 */
public class AlertMailer {
    private final AlertConfiguration cfg;
    private final Logger log;

    public void sendToCatchall(Alert a) {
        String dest = cfg.getEmailCatchall();
        if (dest == null) {
            return;
        }
        log.info("generating catchall mail for {}", dest);

        ArrayList<String> r = new ArrayList<String>();
        r.add(dest);
        sendMail(r, a.getSummary(), a.getPayload());
    }

    private void sendMail(ArrayList<String> recipients, String subject, String body) {
        String smtpCreds;
        try {
            smtpCreds = RuntimeSecrets.interpretSecret(cfg.getSmtpCredentials(), cfg.getGcpProject());
        } catch (IOException exc) {
            log.error("mail submission failed: {}", exc.getMessage());
            return;
        }
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

        Session session = Session.getInstance(props,
            new Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(akeys[0], akeys[1]);
                }
            }
        );

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(cfg.getEmailFrom(), true));
            message.setRecipient(Message.RecipientType.TO,
                new InternetAddress(cfg.getEmailCatchall()));
            message.setSubject(subject);
            message.setText(body);
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
    }
}
