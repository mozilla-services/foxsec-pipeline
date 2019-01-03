package com.mozilla.secops.parser;

class ParserState {
  private final Parser parser;

  public Parser getParser() {
    return parser;
  }

  ParserState(Parser parser) {
    this.parser = parser;
  }
}
