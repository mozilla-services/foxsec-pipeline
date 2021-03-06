package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Detection of an ip attempting to enumerate FxA users through the account status endpoint.
 *
 * <p>Assumed to operate on ten minute fixed windows.
 */
public class CustomsAccountEnumeration
    extends PTransform<PCollection<KV<String, CustomsFeatures>>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;
  private final boolean escalate;
  private final int threshold;
  private final String monitoredResource;
  private final boolean useContentServerVariance;
  private PCollectionView<Map<String, Boolean>> varianceView;
  private final long minVarianceClients;

  private final Logger log = LoggerFactory.getLogger(CustomsAccountEnumeration.class);

  /**
   * Create new CustomsAccountEnumeration
   *
   * @param options Pipeline options
   * @param varianceView Use {@link PCollectionView} for variance, or null to disable
   */
  public CustomsAccountEnumeration(
      Customs.CustomsOptions options, PCollectionView<Map<String, Boolean>> varianceView) {
    this.monitoredResource = options.getMonitoredResourceIndicator();
    this.escalate = options.getEscalateAccountEnumerationDetector();
    this.threshold = options.getAccountEnumerationThreshold();
    this.useContentServerVariance = options.getEnableContentServerVarianceDetection();
    this.minVarianceClients = options.getContentServerVarianceMinClients();
    this.varianceView = varianceView;
  }

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    String varDesc =
        useContentServerVariance
            ? ", using content server variance"
            : ", without using content server variance";
    return String.format(
        "Alert if single source address checks %d or more distinct emails are FxA accounts within 10 minute"
            + " fixed window%s.",
        threshold, varDesc);
  }

  @Override
  public PCollection<Alert> expand(PCollection<KV<String, CustomsFeatures>> col) {
    return col.apply(
            "account enumeration analysis",
            ParDo.of(
                    new DoFn<KV<String, CustomsFeatures>, KV<String, Alert>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        String ipAddr = c.element().getKey();
                        CustomsFeatures cf = c.element().getValue();
                        // If the total status check count is less than the threshold
                        // we don't need to continue
                        if (cf.getTotalAccountStatusCheckCount() < threshold) {
                          return;
                        }

                        // Check if the ip address has made requests other than the status
                        // check endpoint
                        int numPaths = cf.getUniquePathRequestCount().size();
                        if (numPaths > 1) {
                          log.info(
                              "{}: skipping notification, ip has requested {} endpoints",
                              ipAddr,
                              numPaths);
                          return;
                        }

                        // Check the number of distinct accounts checked between all
                        // successful and blocked requests
                        ArrayList<Event> events =
                            cf.getEventsOfType(FxaAuth.EventSummary.ACCOUNT_STATUS_CHECK_SUCCESS);
                        events.addAll(
                            cf.getEventsOfType(FxaAuth.EventSummary.ACCOUNT_STATUS_CHECK_BLOCKED));

                        List<String> emails =
                            events
                                .stream()
                                .map(e -> CustomsUtil.authGetEmail(e))
                                .filter(Objects::nonNull)
                                .distinct()
                                .collect(Collectors.toList());

                        long emailCount = emails.size();
                        if (emailCount < threshold) {
                          return;
                        }

                        if (useContentServerVariance && varianceView != null) {
                          Map<String, Boolean> varianceMap = c.sideInput(varianceView);
                          if (varianceMap.size() < minVarianceClients) {
                            log.info(
                                "{}: skipping notification, not enough clients in content server logs",
                                ipAddr);
                            return;
                          }
                          Boolean isInContentServer = varianceMap.get(ipAddr);
                          if (isInContentServer != null && isInContentServer) {
                            log.info(
                                "{}: skipping notification, found ip in content server", ipAddr);
                            return;
                          }
                        }

                        Alert alert = new Alert();
                        alert.setCategory("customs");
                        alert.setSubcategory(Customs.CATEGORY_ACCOUNT_ENUMERATION);
                        alert.setTimestamp(Parser.getLatestTimestamp(events));
                        alert.setNotifyMergeKey(Customs.CATEGORY_ACCOUNT_ENUMERATION);
                        alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, ipAddr);
                        alert.addMetadata(AlertMeta.Key.COUNT, Long.toString(emailCount));
                        alert.addMetadata(AlertMeta.Key.THRESHOLD, Integer.toString(threshold));
                        alert.setSummary(
                            String.format(
                                "%s %s account enumeration threshold exceeded, %d in 10 minutes",
                                monitoredResource, ipAddr, emailCount));
                        alert.addMetadata(AlertMeta.Key.EMAIL, emails);
                        c.output(KV.of(ipAddr, alert));
                      }
                    })
                .withSideInputs(varianceView))
        .apply("account enumeration global windows", new GlobalTriggers<KV<String, Alert>>(5))
        .apply(ParDo.of(new AlertSuppressorCount(600L)));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
