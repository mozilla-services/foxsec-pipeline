package com.mozilla.secops.gatekeeper.guardduty;

import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

public class GuardDutyParser implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link Event} objects.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private ParserCfg cfg;

    /**
     * Static initializer for {@link Parse} transform
     *
     * @param options Pipeline options
     */
    public Parse(GuardDutyOptions options) {
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> rawCloudWatchEventData) {
      EventFilter filter = new EventFilter();
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GUARDDUTY));

      PCollection<Event> parsed =
          rawCloudWatchEventData.apply(
              ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)));

      return parsed;
    }
  }
}
