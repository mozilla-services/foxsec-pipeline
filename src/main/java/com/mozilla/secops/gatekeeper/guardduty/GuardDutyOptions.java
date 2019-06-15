package com.mozilla.secops.gatekeeper.guardduty;

import com.mozilla.secops.IOOptions;
import org.apache.beam.sdk.options.PipelineOptions;

/** Runtime options for {@link GuardDutyPipeline} . */
public interface GuardDutyOptions extends PipelineOptions, IOOptions {}
