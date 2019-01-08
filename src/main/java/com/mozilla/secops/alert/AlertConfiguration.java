package com.mozilla.secops.alert;

import java.io.Serializable;

/** Configuration for {@link AlertIO} */
public class AlertConfiguration implements Serializable {
  private static final long serialVersionUID = 1L;

  private String smtpCredentials;
  private String smtpRelay;
  private String emailCatchall;
  private String emailFrom;
  private String gcpProject;
  private String slackToken;

  /**
   * Determine if {@link AlertIO} should be established in composite transform
   *
   * @return True if configuration indicates {@link AlertIO} should run
   */
  public Boolean isConfigured() {
    return (smtpCredentials != null);
  }

  /**
   * Get SMTP credentials
   *
   * @return SMTP credential string
   */
  public String getSmtpCredentials() {
    return smtpCredentials;
  }

  /**
   * Set SMTP credentials
   *
   * @param smtpCredentials SMTP credential string
   */
  public void setSmtpCredentials(String smtpCredentials) {
    this.smtpCredentials = smtpCredentials;
  }

  /**
   * Get SMTP relay
   *
   * @return SMTP relay string
   */
  public String getSmtpRelay() {
    return smtpRelay;
  }

  /**
   * Set SMTP relay
   *
   * @param smtpRelay SMTP relay string
   */
  public void setSmtpRelay(String smtpRelay) {
    this.smtpRelay = smtpRelay;
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
   * Get email from address
   *
   * @return From address string
   */
  public String getEmailFrom() {
    return emailFrom;
  }

  /**
   * Set email from address
   *
   * @param emailFrom From address string
   */
  public void setEmailFrom(String emailFrom) {
    this.emailFrom = emailFrom;
  }

  /**
   * Get GCP project name
   *
   * @return Project name string
   */
  public String getGcpProject() {
    return gcpProject;
  }

  /**
   * Set GCP project name
   *
   * @param gcpProject Project name string
   */
  public void setGcpProject(String gcpProject) {
    this.gcpProject = gcpProject;
  }

  public String getSlackToken() {
    return slackToken;
  }

  public void setSlackToken(String slackToken) {
    this.slackToken = slackToken;
  }

  /** Create new empty {@link AlertConfiguration} */
  public AlertConfiguration() {}
}
