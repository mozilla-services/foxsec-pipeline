package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.SecEvent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollectionView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Operate in conjunction with {@link RateLimitAnalyzer} to apply analysis criterion to incoming
 * event stream.
 */
public class RateLimitCriterion extends DoFn<KV<String, Long>, KV<String, Alert>> {
  private static final long serialVersionUID = 1L;

  private final int MAX_SAMPLE = 5;

  private final Alert.AlertSeverity severity;
  private final String customsMeta;
  private final Long limit;
  private final PCollectionView<Map<String, Iterable<Event>>> eventView;

  private Logger log;

  /**
   * {@link RateLimitCriterion} static initializer
   *
   * @param severity Severity to use for generated alerts
   * @param customsMeta Customs metadata tag to place on alert
   * @param limit Generate alert if count meets or exceeds limit value in window
   */
  public RateLimitCriterion(
      Alert.AlertSeverity severity,
      String customsMeta,
      Long limit,
      PCollectionView<Map<String, Iterable<Event>>> eventView) {
    this.severity = severity;
    this.customsMeta = customsMeta;
    this.limit = limit;
    this.eventView = eventView;
  }

  @Setup
  public void setup() {
    log = LoggerFactory.getLogger(RateLimitCriterion.class);
    log.info(
        "initialized new rate limit criterion analyzer, {} {} {}", severity, customsMeta, limit);
  }

  private static String extractActorAccountId(Event e) {
    return e.<SecEvent>getPayload().getSecEventData().getActorAccountId();
  }

  private Boolean uniqueActorAccountId(Iterable<Event> eventList) {
    Event[] events = ((Collection<Event>) eventList).toArray(new Event[0]);
    if (events.length == 0) {
      return false;
    }
    if (events.length == 1) {
      return true;
    }
    String actorComp = extractActorAccountId(events[0]);
    for (Event e : events) {
      if (!(extractActorAccountId(e).equals(actorComp))) {
        return false;
      }
    }
    return true;
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    KV<String, Long> e = c.element();
    Map<String, Iterable<Event>> eventMap = c.sideInput(eventView);

    String key = e.getKey();
    Long valueCount = e.getValue();
    if (valueCount < limit) {
      return;
    }

    // Take a arbitrary sample of any events that were included in the detection window to be added
    // to the alert as metadata
    ArrayList<Event> sample = new ArrayList<Event>();
    Iterable<Event> eventList = eventMap.get(key);
    int i = 0;
    if (eventList != null) {
      for (Event ev : eventList) {
        sample.add(ev);
        if (++i >= MAX_SAMPLE) {
          break;
        }
      }
    }

    Alert alert = new Alert();
    alert.setCategory("customs");
    alert.addMetadata("customs_category", customsMeta);
    alert.addMetadata("customs_suspected", key);
    alert.addMetadata("customs_count", valueCount.toString());
    alert.addMetadata("customs_threshold", limit.toString());
    if (uniqueActorAccountId(eventList)) {
      alert.addMetadata("customs_actor_accountid", extractActorAccountId(sample.get(0)));
    }
    if (sample.size() > 0) {
      alert.addMetadata("customs_sample", Event.iterableToJson(sample));
    }
    alert.setSeverity(severity);
    c.output(KV.of(key, alert));
  }
}
