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
  private String slackCatchall;
  private Boolean memcachedEnabled;
  private String memcachedHost;
  private Integer memcachedPort;
  private Boolean datastoreEnabled;

  /**
   * Determine if {@link AlertIO} should be established in composite transform
   *
   * @return True if configuration indicates {@link AlertIO} should run
   */
  public Boolean isConfigured() {
    return (smtpCredentials != null || slackToken != null);
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

  /**
   * Get slack bot token
   *
   * @return Slack bot token string
   */
  public String getSlackToken() {
    return slackToken;
  }

  /**
   * Set slack bot token
   *
   * @param slackToken Slack bot token string
   */
  public void setSlackToken(String slackToken) {
    this.slackToken = slackToken;
  }

  /**
   * Get slack catchall channel id
   *
   * @return Slack catchall Channel ID string
   */
  public String getSlackCatchall() {
    return slackCatchall;
  }

  /**
   * Set slack catchall channel id
   *
   * @param slackCatchall Slack catchall Channel ID string
   */
  public void setSlackCatchall(String slackCatchall) {
    this.slackCatchall = slackCatchall;
  }

  /**
   * Set memcached enabled boolean for alert state management
   *
   * @param memcachedEnabled Boolean, true if alert state management should use memcached.
   */
  public void setMemcachedEnabled(Boolean memcachedEnabled) {
    this.memcachedEnabled = memcachedEnabled;
  }

  /**
   * Get memcached enabled boolean
   *
   * @return Boolean, true if alert state management should use memcached.
   */
  public Boolean getMemcachedEnabled() {
    return memcachedEnabled;
  }

  /**
   * Set memcached host
   *
   * @param memcachedHost memcached host
   */
  public void setMemcachedHost(String memcachedHost) {
    this.memcachedHost = memcachedHost;
  }

  /**
   * Get memcached host
   *
   * @return memcached host
   */
  public String getMemcachedHost() {
    return memcachedHost;
  }

  /**
   * Set memcached port
   *
   * @param memcachedPort memcached port
   */
  public void setMemcachedPort(Integer memcachedPort) {
    this.memcachedPort = memcachedPort;
  }

  /**
   * Get memcached port
   *
   * @return memcached port
   */
  public Integer getMemcachedPort() {
    return memcachedPort;
  }

  /**
   * Set datastore enabled boolean for alert state management
   *
   * @param datastoreEnabled Boolean, true if alert state management should use datastore.
   */
  public void setDatastoreEnabled(Boolean datastoreEnabled) {
    this.datastoreEnabled = datastoreEnabled;
  }

  /**
   * Get datastore enabled boolean
   *
   * @return Boolean, true if alert state management should use memcached.
   */
  public Boolean getDatastoreEnabled() {
    return datastoreEnabled;
  }

  /** Create new empty {@link AlertConfiguration} */
  public AlertConfiguration() {}
}
