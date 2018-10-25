package com.mozilla.secops.alert;

import java.io.Serializable;

/**
 * Configuration for {@link AlertIO}
 */
public class AlertConfiguration implements Serializable {
    private static final long serialVersionUID = 1L;

    private String sesCredentials;
    private String emailCatchall;

    /**
     * Determine if {@link AlertIO} should be established in composite transform
     *
     * @return True if configuration indicates {@link AlertIO} should run
     */
    public Boolean isConfigured() {
        return (sesCredentials != null);
    }

    /**
     * Get SES credentials
     *
     * @return SES credential string
     */
    public String getSesCredentials() {
        return sesCredentials;
    }

    /**
     * Set SES credentials
     *
     * @param sesCredentials SES credential string
     */
    public void setSesCredentials(String sesCredentials) {
        this.sesCredentials = sesCredentials;
    }

    /**
     * Get email catchall address
     *
     * @return Email address string
     */
    public String getEmailCatchall() {
        return emailCatchall;
    }

    /**
     * Set email catchall address
     *
     * @param emailCatchall Catchall email address
     */
    public void setEmailCatchall(String emailCatchall) {
        this.emailCatchall = emailCatchall;
    }

    /**
     * Create new empty {@link AlertConfiguration}
     */
    public AlertConfiguration() {
    }
}
