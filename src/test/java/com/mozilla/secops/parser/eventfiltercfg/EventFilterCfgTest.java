package com.mozilla.secops.parser.eventfiltercfg;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Parser;
import org.junit.Test;

public class EventFilterCfgTest {
  public EventFilterCfgTest() {}

  @Test
  public void eventFilterCfgNoop() throws Exception {
    EventFilterCfg c = new EventFilterCfg();
    assertNotNull(c);
  }

  @Test
  public void eventFilterLoadJson() throws Exception {
    String buf =
        "{\"secevent_version\":\"secevent.model.1\",\"action\":\"loginFailure\""
            + ",\"account_id\":\"q@the-q-continuum\",\"timestamp\":\"1970-01-01T00:00:00+00:00\"}";

    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);

    EventFilterCfg c = EventFilterCfg.loadFromResource("/testdata/eventfilterconfig.json");
    assertNotNull(c);
    assertTrue(c.getEventFilter("testfilter1").matches(e));
    assertFalse(c.getEventFilter("testfilter2").matches(e));
    assertFalse(c.getEventFilter("testfilter3").matches(e));
  }
}
