package com.mozilla.secops.parser.models.aws.guardduty;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.io.Serializable;

/** Describes the format of a AWS GuardDuty Finding */
@JsonIgnoreProperties(ignoreUnknown = true)
public class GuardDutyFinding implements Serializable {
  private static final long serialVersionUID = 1L;

  // TODO
}
