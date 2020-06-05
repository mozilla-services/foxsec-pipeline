package com.mozilla.secops.customs;

import com.mozilla.secops.FileUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Objects;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Customs status check comparator */
public class CustomsStatusComparator extends PTransform<PCollection<Event>, PCollection<Alert>>
    implements CustomsDocumentingTransform {
  private static final long serialVersionUID = 1L;

  private static final String COMPARATOR_KIND = "customs_status_comparator";
  private final String monitoredResource;
  private final String addressPath;
  private final String memcachedHost;
  private final Integer memcachedPort;
  private final String datastoreNamespace;

  private final Logger log = LoggerFactory.getLogger(CustomsStatusComparator.class);

  private boolean escalate;

  /** {@inheritDoc} */
  public String getTransformDocDescription() {
    return "Generate alerts if status checks occur flagged by comparator operation.";
  }

  private static class ComparatorElement implements Serializable {
    private static final long serialVersionUID = 1L;

    public String address;
    public String email;

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof ComparatorElement)) {
        return false;
      }
      ComparatorElement d = (ComparatorElement) o;
      return address.equals(d.address) && email.equals(d.email);
    }

    @Override
    public int hashCode() {
      return Objects.hash(address, email);
    }

    ComparatorElement(String address, String email) {
      this.address = address;
      this.email = email;
    }
  }

  /**
   * Initialize new CustomsStatusComparator
   *
   * @param options Pipeline options
   */
  public CustomsStatusComparator(Customs.CustomsOptions options) {
    monitoredResource = options.getMonitoredResourceIndicator();
    addressPath = options.getStatusComparatorAddressPath();
    escalate = options.getEscalateStatusComparator();
    memcachedHost = options.getMemcachedHost();
    memcachedPort = options.getMemcachedPort();
    datastoreNamespace = options.getDatastoreNamespace();
  }

  @Override
  public PCollection<Alert> expand(PCollection<Event> col) {
    return col.apply(
            "status comparator filter events",
            ParDo.of(
                new DoFn<Event, ComparatorElement>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();

                    FxaAuth.EventSummary sum = CustomsUtil.authGetEventSummary(e);

                    if (!(sum == FxaAuth.EventSummary.ACCOUNT_STATUS_CHECK_SUCCESS)) {
                      return;
                    }

                    if (CustomsUtil.authGetSourceAddress(e) == null) {
                      return;
                    }

                    if (CustomsUtil.authGetEmail(e) == null) {
                      return;
                    }

                    c.output(
                        new ComparatorElement(
                            CustomsUtil.authGetSourceAddress(e), CustomsUtil.authGetEmail(e)));
                  }
                }))
        .apply(
            "status comparator window",
            Window.<ComparatorElement>into(FixedWindows.of(Duration.standardMinutes(5))))
        .apply(
            "status comparator analyze",
            ParDo.of(
                new DoFn<ComparatorElement, Alert>() {
                  private static final long serialVersionUID = 1L;

                  private ArrayList<String> addrlist;
                  private State state;

                  @Setup
                  public void setup() throws IOException {
                    log.info("loading address list from {}", addressPath);
                    addrlist = FileUtil.fileReadLines(addressPath);
                    if (memcachedHost != null && memcachedPort != null) {
                      log.info("using memcached for state management");
                      state = new State(new MemcachedStateInterface(memcachedHost, memcachedPort));
                    } else if (datastoreNamespace != null) {
                      log.info("using datastore for state management");
                      state =
                          new State(new DatastoreStateInterface(VELOCITY_KIND, datastoreNamespace));
                    } else {
                      throw new IllegalArgumentException(
                          "could not find valid state parameters in options");
                    }
                    state.initialize();
                  }

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    ComparatorElement e = c.element();

                    if (!addrlist.contains(e.address)) {
                      return;
                    }
                    log.info("comparator match on {} for {}", e.address, e.email);

                    Alert alert = new Alert();
                    alert.setCategory("customs");
                    alert.setSubcategory(Customs.CATEGORY_STATUS_COMPARATOR);
                    alert.setNotifyMergeKey(Customs.CATEGORY_STATUS_COMPARATOR);
                    alert.addMetadata(AlertMeta.Key.EMAIL, e.email);
                    alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, e.address);
                    alert.setSummary(
                        String.format(
                            "%s status check comparator indicates known address",
                            monitoredResource));

                    c.output(alert);
                  }
                }))
        .apply("status comparator global windows", new GlobalTriggers<Alert>(5));
  }

  public boolean isExperimental() {
    return !escalate;
  }
}
