package com.mozilla.secops.awsbehavior;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.mozilla.secops.parser.EventFilterRule;
import org.junit.Test;

public class TestCloudtrailMatcherManager {
  public TestCloudtrailMatcherManager() {}

  @Test
  public void cloudtrailMatcherManagerFromResourceTest() throws Exception {
    CloudtrailMatcherManager mgr =
        CloudtrailMatcherManager.loadFromResource("/testdata/event_matchers.json");
    assertNotNull(mgr);

    assertEquals(mgr.getEventMatchers().size(), 2);

    CloudtrailMatcher cm = mgr.getEventMatchers().get(0);
    assertNotNull(cm);

    assertEquals(cm.getDescription(), "access key created");

    EventFilterRule efr = cm.toEventFilterRule();
    assertNotNull(efr);
  }
}
