package com.mozilla.secops;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.KeyedEvent;
import com.mozilla.secops.parser.Parser;
import java.io.IOException;
import org.apache.beam.sdk.values.KV;
import org.junit.Test;

public class TestScriptRunner {
  public TestScriptRunner() {}

  @Test
  public void scriptRunnerTestCreate() throws Exception {
    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
  }

  @Test
  public void scriptRunnerTestRun() throws Exception {
    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
    s.loadScript("/testdata/groovy/test.groovy", "test");
    assertNull(s.invokeMethod("test", "noop", Object.class, new Object[] {}));
  }

  @Test
  public void scriptRunnerTestRunInc() throws Exception {
    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
    s.loadScript("/testdata/groovy/test.groovy", "test");
    Object ret = s.invokeMethod("test", "inc", Integer.class, new Object[] {1});
    assertEquals(2, (int) ret);
  }

  @Test
  public void scriptRunnerTestRunAdd() throws Exception {
    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
    s.loadScript("/testdata/groovy/test.groovy", "test");
    Object ret = s.invokeMethod("test", "add", Integer.class, new Object[] {2, 3});
    assertEquals(5, (int) ret);
  }

  @Test
  public void scriptRunnerTestRunFilterKeyEvent() throws Exception {
    String buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_"
            + "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\""
            + ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999"
            + "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\""
            + "textPayload\":\"Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
            + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp"
            + "\":\"2018-09-18T22:15:38Z\"}";

    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
    s.loadScript("/testdata/groovy/test.groovy", "test");

    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    KeyedEvent ke = s.invokeMethod("test", "eventHandler", KeyedEvent.class, new Object[] {e});
    assertNotNull(ke);
    KV<String, Event> kv = ke.toKV();
    assertNotNull(kv);
    assertEquals("riker", kv.getKey());
    assertEquals("2018-09-18T22:15:38.000Z", kv.getValue().getTimestamp().toString());
  }

  @Test(expected = IllegalArgumentException.class)
  public void scriptRunnerTestRunNoMethod() throws Exception {
    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
    s.loadScript("/testdata/groovy/test.groovy", "test");
    s.invokeMethod("test", "nonexistent", Object.class, new Object[] {});
  }

  @Test(expected = IOException.class)
  public void scriptRunnerTestLoadNotFound() throws Exception {
    ScriptRunner s = new ScriptRunner();
    assertNotNull(s);
    s.loadScript("/testdata/groovy/nonexistent.groovy", "nonexistent");
  }
}
