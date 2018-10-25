package com.mozilla.secops.alert;

/**
 * {@link AlertMailer} handles SES based alerting output
 */
public class AlertMailer {
    private final AlertConfiguration cfg;

    public void sendToCatchall(Alert a) {
    }

    /**
     * Create new {@link AlertMailer} with specified {@link AlertConfiguration}
     *
     * @param cfg {@link AlertConfiguration}
     */
    public AlertMailer(AlertConfiguration cfg) {
        this.cfg = cfg;
    }
}
