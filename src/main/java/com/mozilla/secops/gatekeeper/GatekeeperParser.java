package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.Serializable;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/**
 * Implements a parser which handles both AWS GuardDuty {@link
 * com.amazonaws.services.guardduty.model.Finding} and GCP ETD Findings {@link
 * com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding}
 *
 * <p>AWS GuardDuty findings are likely to be wrapped in CloudWatch Event logs {@link
 * com.mozilla.secops.parser.models.cloudwatch.CloudWatchEvent} and GCP ETD findings are likely to
 * be wrapped in Stackdriver logs.
 *
 * <p>The parser is capable of handling wrapped or unwrapped findings for both services
 */
public class GatekeeperParser implements Serializable {
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
    public Parse(GatekeeperPipeline.GatekeeperOptions options) {
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> rawInputStrings) {
      EventFilter filter = new EventFilter().passConfigurationTicks();
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GUARDDUTY));
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.ETD));

      PCollection<Event> parsed =
          rawInputStrings.apply(
              ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)));

      return parsed;
    }
  }
}
