package com.mozilla.secops.httprequest;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/**
 * Post-input filter for per-element analysis
 *
 * <p>The primary intent of this transform is perform any pre-analysis filtering of events for a
 * given resource. Currently only network address/cidr filtering is performed here.
 */
public class HTTPRequestElementFilter extends PTransform<PCollection<Event>, PCollection<Event>> {
  private static final long serialVersionUID = 1L;

  private final Boolean ignoreCp;
  private final Boolean ignoreInternal;
  private final String cidrExclusionList;

  /**
   * Initialize new element filter
   *
   * @param toggles Per-element toggles
   */
  public HTTPRequestElementFilter(HTTPRequestToggles toggles) {
    ignoreCp = toggles.getIgnoreCloudProviderRequests();
    ignoreInternal = toggles.getIgnoreInternalRequests();
    cidrExclusionList = toggles.getCidrExclusionList();
  }

  @Override
  public PCollection<Event> expand(PCollection<Event> col) {
    int exclmask = 0;
    if (cidrExclusionList != null) {
      exclmask |= CidrUtil.CIDRUTIL_FILE;
    }
    if (ignoreCp) {
      exclmask |= CidrUtil.CIDRUTIL_CLOUDPROVIDERS;
    }
    if (ignoreInternal) {
      exclmask |= CidrUtil.CIDRUTIL_INTERNAL;
    }
    if (exclmask != 0) {
      return col.apply(
          "cidr exclusion",
          ParDo.of(CidrUtil.excludeNormalizedSourceAddresses(exclmask, cidrExclusionList)));
    }
    return col;
  }
}
