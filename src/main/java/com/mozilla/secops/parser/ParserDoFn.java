package com.mozilla.secops.parser;

import org.apache.beam.sdk.transforms.DoFn;

/** {@link DoFn} applying simple event parsing operations */
public class ParserDoFn extends DoFn<String, Event> {
  private static final long serialVersionUID = 1L;

  private Parser ep;

  private EventFilter inlineFilter;
  private ParserCfg cfg;

  /**
   * Install an inline {@link EventFilter} in this transform
   *
   * <p>If an inline filter is present in the transform, the transform will only emit events that
   * match the filter.
   *
   * @param inlineFilter Event filter to install
   * @return ParserDoFn
   */
  public ParserDoFn withInlineEventFilter(EventFilter inlineFilter) {
    this.inlineFilter = inlineFilter;
    return this;
  }

  /**
   * Configure this function to use the specified configuration in the parser
   *
   * @param cfg Parser configuration
   * @return ParserDoFn
   */
  public ParserDoFn withConfiguration(ParserCfg cfg) {
    this.cfg = cfg;
    return this;
  }

  @Setup
  public void setup() {
    if (cfg == null) {
      ep = new Parser();
    } else {
      ep = new Parser(cfg);
    }
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Event e = ep.parse(c.element());
    if (e != null) {
      if (inlineFilter != null) {
        if (!(inlineFilter.matches(e))) {
          return;
        }
        if (inlineFilter.getOutputWithTimestamp()) {
          c.outputWithTimestamp(e, e.getTimestamp().toInstant());
          return;
        }
      }
      c.output(e);
    }
  }
}
