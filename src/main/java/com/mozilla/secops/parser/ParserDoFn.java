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

  private EventFilter inlineFilter;
  private String geoIpDbPath;

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
   * Enable GeoIP resolution in this parser function
   *
   * @param geoIpDbPath Path to Maxmind DB
   * @return ParserDoFn
   */
  public ParserDoFn withGeoIP(String geoIpDbPath) {
    this.geoIpDbPath = geoIpDbPath;
    return this;
  }

  @Setup
  public void setup() {
    ep = new Parser();
    if (geoIpDbPath != null) {
      ep.enableGeoIp(geoIpDbPath);
    }
    log = LoggerFactory.getLogger(ParserDoFn.class);
  }

  @StartBundle
  public void StartBundle() {
    parseCount = 0L;
  }

  @FinishBundle
  public void FinishBundle() {
    if (parseCount > 0L) {
      log.info("{} events processed in bundle", parseCount);
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
          parseCount++;
          c.outputWithTimestamp(e, e.getTimestamp().toInstant());
          return;
        }
      }
      parseCount++;
      c.output(e);
    }
  }
}
