package com.mozilla.secops.parser;

import com.google.api.services.logging.v2.model.LogEntry;

/** Stores per-event state of parser */
class ParserState {
  private final Parser parser;
  private LogEntry logEntryHint;
  private Mozlog mozLogHint;
  private com.google.api.client.json.jackson2.JacksonFactory googleJacksonFactory;

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
}
