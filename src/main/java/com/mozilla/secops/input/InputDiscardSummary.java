package com.mozilla.secops.input;

import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Summarize input discard events */
public class InputDiscardSummary extends PTransform<PCollection<Event>, PDone> {
  private static final long serialVersionUID = 1L;

  private static final String UNKNOWN_DISCARD = "unknown_discard";
  private static final String INLINE_FILTER_MISMATCH = "inline_filter_mismatch";
  private static final String FASTMATCH_MISMATCH = "fastmatch_mismatch";
  private static final String COMMON_INPUT_FILTER_MISMATCH = "common_input_filter_mismatch";
  private static final String TIMESTAMP_TOO_OLD = "timestamp_too_old";

  private String name;
  private Logger log;

  /**
   * Create new InputDiscardSummary
   *
   * @param name Element name
   */
  public InputDiscardSummary(String name) {
    this.name = name;
    log = LoggerFactory.getLogger(InputDiscardSummary.class);
  }

  @Override
  public PDone expand(PCollection<Event> input) {
    input
        .apply(
            "discard extract type",
            ParDo.of(
                new DoFn<Event, String>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();
                    switch (e.getEventFlag()) {
                      case FLAG_OK:
                        // This should never happen
                        throw new RuntimeException("FLAG_OK in InputDiscardSummary");
                      case FLAG_INLINE_FILTER_MISMATCH:
                        c.output(INLINE_FILTER_MISMATCH);
                        break;
                      case FLAG_FASTMATCH_MISMATCH:
                        c.output(FASTMATCH_MISMATCH);
                        break;
                      case FLAG_COMMON_INPUT_FILTER_MISMATCH:
                        c.output(COMMON_INPUT_FILTER_MISMATCH);
                        break;
                      case FLAG_TIMESTAMP_TOO_OLD:
                        c.output(TIMESTAMP_TOO_OLD);
                        break;
                      default:
                        c.output(UNKNOWN_DISCARD);
                        break;
                    }
                  }
                }))
        .apply(Window.<String>into(FixedWindows.of(Duration.standardMinutes(5))))
        .apply(Count.perElement())
        .apply(
            "discard summary",
            ParDo.of(
                new DoFn<KV<String, Long>, Void>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    log.info(
                        "input discard summary: {}: {} {}",
                        name,
                        c.element().getKey(),
                        c.element().getValue());
                  }
                }));
    return PDone.in(input.getPipeline());
  }
}
