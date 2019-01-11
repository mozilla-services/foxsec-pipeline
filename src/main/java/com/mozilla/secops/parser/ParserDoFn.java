package com.mozilla.secops.parser;

import org.apache.beam.sdk.transforms.DoFn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link DoFn} applying simple event parsing operations */
public class ParserDoFn extends DoFn<String, Event> {
  private static final long serialVersionUID = 1L;

  private Logger log;
  private Parser ep;
  private Long parseCount;

  private String stackdriverProjectFilter;

  /**
   * Return a parser that filters any Stackdriver LogEntry message that does not originate from the
   * specified project
   *
   * <p>Any events that are seen that are not Stackdriver events will just be passed as is.
   *
   * @param project Project name
   * @return Parser DoFn
   */
  public ParserDoFn withStackdriverProjectFilter(String project) {
    stackdriverProjectFilter = project;
    return this;
  }

  @Setup
  public void setup() {
    ep = new Parser();
    log = LoggerFactory.getLogger(ParserDoFn.class);
    log.info("initialized new parser");
    if (stackdriverProjectFilter != null) {
      log.info("installing stackdriver project filter for {}", stackdriverProjectFilter);
      ep.installStackdriverProjectFilter(stackdriverProjectFilter);
    }
  }

  @StartBundle
  public void StartBundle() {
    log.info("processing new bundle");
    parseCount = 0L;
  }

  @FinishBundle
  public void FinishBundle() {
    log.info("{} events processed in bundle", parseCount);
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Event e = ep.parse(c.element());
    if (e != null) {
      parseCount++;
      c.output(e);
    }
  }
}
