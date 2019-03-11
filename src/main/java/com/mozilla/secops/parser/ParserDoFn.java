package com.mozilla.secops.parser;

import com.mozilla.secops.identity.IdentityManager;
import java.io.IOException;
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
  private ParserCfg cfg;
  private String idmanagerPath;

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

  public ParserDoFn withIdentityManagerFromPath(String idmanagerPath) {
    this.idmanagerPath = idmanagerPath;
    return this;
  }

  @Setup
  public void setup() {
    if (cfg == null) {
      ep = new Parser();
    } else {
      ep = new Parser(cfg);
    }
    log = LoggerFactory.getLogger(ParserDoFn.class);

    try {
      IdentityManager mgr;
      if (idmanagerPath == null) {
        mgr = IdentityManager.load();
      } else {
        mgr = IdentityManager.load(idmanagerPath);
      }
      ep.setIdentityManager(mgr);
    } catch (IOException exc) {
      log.warn("could not load identity manager within ParserDoFn: {}", exc.getMessage());
    }
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
