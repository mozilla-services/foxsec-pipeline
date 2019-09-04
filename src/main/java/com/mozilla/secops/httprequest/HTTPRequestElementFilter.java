package com.mozilla.secops.httprequest;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/**
 * Post-input filter for per-element analysis
 *
 * <p>The primary intent of this transform is filtering an event stream to ensure it contains only
 * events for the desired element. Additional filtering such as network address/CIDR based filtering
 * also occurs here.
 */
public class HTTPRequestElementFilter
    extends PTransform<PCollection<KV<String, Event>>, PCollection<Event>> {
  private static final long serialVersionUID = 1L;

  private String name;

  private Boolean ignoreCp;
  private Boolean ignoreInternal;
  private String cidrExclusionList;

  /**
   * Initialize new element filter
   *
   * @param name Resource name that we want, all others will be filtered
   * @param toggles Per-element toggles
   */
  public HTTPRequestElementFilter(String name, HTTPRequestToggles toggles) {
    this.name = name;

    ignoreCp = toggles.getIgnoreCloudProviderRequests();
    ignoreInternal = toggles.getIgnoreInternalRequests();
    cidrExclusionList = toggles.getCidrExclusionList();
  }

  @Override
  public PCollection<Event> expand(PCollection<KV<String, Event>> col) {
    PCollection<Event> events =
        col.apply(
            "filter keys for element",
            ParDo.of(
                new DoFn<KV<String, Event>, Event>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    KV<String, Event> e = c.element();
                    if (e.getKey().equals(name)) {
                      c.output(e.getValue());
                    }
                  }
                }));
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
      return events.apply(
          "cidr exclusion",
          ParDo.of(CidrUtil.excludeNormalizedSourceAddresses(exclmask, cidrExclusionList)));
    }
    return events;
  }
}
