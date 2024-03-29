package com.mozilla.secops.parser;

import org.apache.beam.sdk.transforms.DoFn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link DoFn} applying simple event parsing operations */
public class ParserDoFn extends DoFn<String, Event> {
  private static final long serialVersionUID = 1L;

  private Parser ep;

  private EventFilter inlineFilter;
  private EventFilter commonInputFilter;
  private ParserCfg cfg;

  private Logger log = LoggerFactory.getLogger(ParserDoFn.class);

  private final ParserMetrics metrics = new ParserMetrics(null);

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

    // See if we had any common input options included in the parser configuration
    // that we would want to generate a common input filter for. If so, we will initialize
    // the common input filter and apply it prior to passing the event through any
    // inline event filter configured by the calling pipeline.
    if ((cfg != null)
        && ((cfg.getStackdriverLabelFilters() != null)
            || (cfg.getStackdriverProjectFilter() != null))) {
      commonInputFilter = new EventFilter().passConfigurationTicks();
      EventFilterRule rule = new EventFilterRule();

      if (cfg.getStackdriverLabelFilters() != null) {
        for (String labelFilter : cfg.getStackdriverLabelFilters()) {
          String parts[] = labelFilter.split(":");
          if (parts.length != 2) {
            throw new IllegalArgumentException(
                "invalid format for Stackdriver label filter, must be <key>:<value>");
          }
          rule.wantStackdriverLabel(parts[0], parts[1]);
        }
      }

      if (cfg.getStackdriverProjectFilter() != null) {
        rule.wantStackdriverProject(cfg.getStackdriverProjectFilter());
      }

      commonInputFilter.addRule(rule);
    }
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Event e;
    try {
      e = ep.parse(c.element());
    } catch (Parser.EventTooOldException exc) {
      metrics.eventTooOld();
      return;
    } catch (Throwable t) {
      // rather than blindly catch errors and log we should likely have
      // output errors as a separate tag, we're unlikely to replay messages
      // though so this is a low effort "solution"
      log.info("Unhandled exception: {} parsing element: {}", t.toString(), c.element());
      metrics.eventUnhandledException();
      return;
    }
    if (e != null) {
      // If a common input filter has been configured, apply that first
      if (commonInputFilter != null) {
        if (!(commonInputFilter.matches(e))) {
          return;
        }
      }

      if (inlineFilter != null) {
        if (!(inlineFilter.matches(e))) {
          return;
        }
      }

      // increment payload counter before filtering
      metrics.eventOfPayload(e.getPayloadType());

      if ((cfg != null) && cfg.getUseEventTimestamp()) {
        c.outputWithTimestamp(e, e.getTimestamp().toInstant());
      } else {
        c.output(e);
      }
    }
  }
}
