package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.services.logging.v2.model.LogEntry;
import com.mozilla.secops.parser.models.cloudwatch.CloudWatchEvent;
import com.mozilla.secops.parser.models.cloudwatch.CloudWatchLogEvent;
import com.mozilla.secops.parser.models.cloudwatch.CloudWatchLogSubscription;

/** Stores per-event state of parser */
class ParserState {
  private final Parser parser;
  private LogEntry logEntryHint;
  private CloudWatchEvent cloudwatchEvent;
  private CloudWatchLogEvent cloudwatchLogEvent;
  private CloudWatchLogSubscription cloudwatchLogSubscription;
  private Mozlog mozLogHint;
  private com.google.api.client.json.jackson2.JacksonFactory googleJacksonFactory;
  private ObjectMapper mapper;
  private String stackdriverTypeValue;

  /**
   * Set Stackdriver type value
   *
   * @param stackdriverTypeValue String
   */
  public void setStackdriverTypeValue(String stackdriverTypeValue) {
    this.stackdriverTypeValue = stackdriverTypeValue;
  }

  /**
   * Get Stackdriver type value
   *
   * @return String, or null if unset
   */
  public String getStackdriverTypeValue() {
    return stackdriverTypeValue;
  }

  /**
   * Get LogEntry hint
   *
   * @return hint or null if it has not been set
   */
  public LogEntry getLogEntryHint() {
    return logEntryHint;
  }

  /**
   * Set LogEntry hint
   *
   * @param entry LogEntry to store as hint
   */
  public void setLogEntryHint(LogEntry entry) {
    logEntryHint = entry;
  }

  /**
   * Get cloudwatch event value
   *
   * @return {@link CloudWatchEvent} value or null if not available
   */
  public CloudWatchEvent getCloudWatchEvent() {
    return cloudwatchEvent;
  }

  /**
   * Set cloudwatch event value
   *
   * @param cwe CloudWatchEvent encapsulating generic AWS event
   */
  public void setCloudWatchEvent(CloudWatchEvent cwe) {
    this.cloudwatchEvent = cwe;
  }

  /**
   * Get Mozlog hint
   *
   * @return hint or null of it has not been set
   */
  public Mozlog getMozlogHint() {
    return mozLogHint;
  }

  /**
   * Set Mozlog hint
   *
   * @param entry Mozlog to store as hint
   */
  public void setMozlogHint(Mozlog entry) {
    mozLogHint = entry;
  }

  /**
   * Set Google JacksonFactory
   *
   * @param googleJacksonFactory JacksonFactory
   */
  public void setGoogleJacksonFactory(
      com.google.api.client.json.jackson2.JacksonFactory googleJacksonFactory) {
    this.googleJacksonFactory = googleJacksonFactory;
  }

  /**
   * Get Google JacksonFactory
   *
   * @return JacksonFactory, or null if unset
   */
  public com.google.api.client.json.jackson2.JacksonFactory getGoogleJacksonFactory() {
    return googleJacksonFactory;
  }

  /**
   * Set ObjectMapper
   *
   * @param mapper ObjectMapper
   */
  public void setObjectMapper(ObjectMapper mapper) {
    this.mapper = mapper;
  }

  /**
   * Get ObjectMapper
   *
   * @return ObjectMapper, or null if unset
   */
  public ObjectMapper getObjectMapper() {
    return mapper;
  }

  /**
   * Get {@link Parser} associated with this state object
   *
   * @return Associated parser
   */
  public Parser getParser() {
    return parser;
  }

  /**
   * Construct new {@link ParserState}
   *
   * @param parser Associated parser instance
   */
  ParserState(Parser parser) {
    this.parser = parser;
  }

  /**
   * Get cloudwatch log event value
   *
   * @return {@link CloudWatchEvent} value or null if not available
   */
  public CloudWatchLogEvent getCloudwatchLogEvent() {
    return cloudwatchLogEvent;
  }

  /**
   * Set cloudwatch log event hint
   *
   * @param cwle CloudWatchLogEvent to store as hint
   */
  public void setCloudwatchLogEvent(CloudWatchLogEvent cwle) {
    this.cloudwatchLogEvent = cwle;
  }

  /**
   * Get cloudwatch log event value
   *
   * @return {@link CloudWatchEvent} value or null if not available
   */
  public CloudWatchLogSubscription getCloudwatchLogSubscription() {
    return cloudwatchLogSubscription;
  }

  /**
   * Set cloudwatch log event hint
   *
   * @param cwle CloudWatchLogEvent to store as hint
   */
  public void setCloudwatchLogSubscription(CloudWatchLogSubscription cwls) {
    this.cloudwatchLogSubscription = cwls;
  }
}
