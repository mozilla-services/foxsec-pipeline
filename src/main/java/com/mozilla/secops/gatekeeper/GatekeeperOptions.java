package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.IOOptions;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;

/** Runtime options for {@link GatekeeperPipeline} . */
public interface GatekeeperOptions extends PipelineOptions, IOOptions {
  @Description("Ignore ETD Findings for any finding rules that match regex (multiple allowed)")
  String[] getIgnoreETDFindingRuleRegex();

  void setIgnoreETDFindingRuleRegex(String[] value);

  @Description(
      "Ignore GuardDuty Findings for any finding types that match regex (multiple allowed)")
  String[] getIgnoreGDFindingTypeRegex();

  void setIgnoreGDFindingTypeRegex(String[] value);
}
