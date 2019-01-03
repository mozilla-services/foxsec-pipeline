package com.mozilla.secops.parser;

import com.google.api.services.logging.v2.model.LogEntry;

/** Stores per-event state of parser */
class ParserState {
  private final Parser parser;
  private LogEntry logEntryHint;

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
