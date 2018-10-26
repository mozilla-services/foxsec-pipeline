package com.mozilla.secops.alert;

import com.amazonaws.regions.Regions;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.services.simpleemail.model.Body;
import com.amazonaws.services.simpleemail.model.Content;
import com.amazonaws.services.simpleemail.model.Destination;
import com.amazonaws.services.simpleemail.model.Message;
import com.amazonaws.services.simpleemail.model.SendEmailRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.crypto.RuntimeSecrets;

import java.io.IOException;
import java.util.ArrayList;

/**
 * {@link AlertMailer} handles SES based alerting output
 */
public class AlertMailer {
    private final String REGION = Regions.US_WEST_2.getName();

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
        String awsCreds;
        try {
            awsCreds = RuntimeSecrets.interpretSecret(cfg.getSesCredentials(), cfg.getGcpProject());
        } catch (IOException exc) {
            log.error("mail submission failed: {}", exc.getMessage());
            return;
        }
        String[] akeys = awsCreds.split(":");
        if (akeys.length != 2) {
            log.error("mail submission failed: invalid SES credentials specified");
            return;
        }

        AmazonSimpleEmailService client = AmazonSimpleEmailServiceClientBuilder.standard()
            .withRegion(REGION)
            .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(akeys[0], akeys[1])))
            .build();
        SendEmailRequest request = new SendEmailRequest()
            .withDestination(new Destination().withToAddresses(recipients))
            .withMessage(new Message()
                .withBody(new Body()
                    .withText(new Content().withCharset("UTF-8").withData(body)))
                .withSubject(new Content()
                    .withCharset("UTF-8").withData(subject)))
            .withSource(cfg.getEmailFrom());
        System.out.println(request);
        client.sendEmail(request);
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
