package com.mozilla.secops.alert;

import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
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
  private State state;

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
   * Get {@link State} obj
   *
   * @return State obj
   */
  public State getState() {
    return state;
  }

  /**
   * Set {@link State} using {@link MemcachedStateInterface}
   *
   * @param host Hostname of memcached instance
   * @param port Port of memcached instance
   */
  public void setMemcachedState(String host, Integer port) {
    this.state = new State(new MemcachedStateInterface(host, port));
  }

  /** Set {@link State} using {@link DatastoreStateInterface} */
  public void setDatastoreState() {
    this.state = new State(new DatastoreStateInterface("alerts", "alerts"));
  }

  /** Create new empty {@link AlertConfiguration} */
  public AlertConfiguration() {}
}
