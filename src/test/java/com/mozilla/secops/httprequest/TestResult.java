package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.mozilla.secops.Violation;
import java.util.UUID;
import org.junit.Test;

public class TestResult {
  public TestResult() {}

  @Test
  public void testClientErrorResultFromJSON() throws Exception {
    String buf =
        "{\"source_address\":\"10.0.0.1\",\"window_timestamp\":\"1970-01-01T00:00:59.999Z\","
            + "\"id\":\"81ad7561-7b83-4dcb-9821-a125431ea02e\",\"type\":\"clienterror\","
            + "\"client_error_count\":60,\"max_client_errors\":30}";
    Result r = Result.fromJSON(buf);
    assertNotNull(r);
    assertEquals(Result.ResultType.CLIENT_ERROR, r.getResultType());
    assertEquals(60L, (long) r.getClientErrorCount());
    assertEquals(30L, (long) r.getMaxClientErrorRate());
    assertEquals("10.0.0.1", r.getSourceAddress());
    assertEquals(UUID.fromString("81ad7561-7b83-4dcb-9821-a125431ea02e"), r.getResultId());
    assertEquals(59999L, r.getWindowTimestamp().getMillis());

    Violation v = r.toViolation();
    assertNotNull(v);
    assertEquals("client_error_rate_violation", v.getViolation());
    assertEquals("10.0.0.1", v.getSourceAddress());
  }

  @Test
  public void testThresholdResultFromJSON() throws Exception {
    String buf =
        "{\"source_address\":\"10.0.0.2\",\"window_timestamp\":\"1970-01-01T00:00:59.999Z\","
            + "\"id\":\"b64fcdb5-0ca2-4598-8903-863d7a29467e\",\"type\":\"thresholdanalysis\",\"count\":900,"
            + "\"mean_value\":200.0,\"threshold_modifier\":1.0}";
    Result r = Result.fromJSON(buf);
    assertNotNull(r);
    assertEquals(Result.ResultType.THRESHOLD_ANALYSIS, r.getResultType());
    assertEquals(900L, (long) r.getCount());
    assertEquals(1.0, (double) r.getThresholdModifier(), 0.1);
    assertEquals(200.0, (double) r.getMeanValue(), 0.1);
    assertEquals("10.0.0.2", r.getSourceAddress());
    assertEquals(UUID.fromString("b64fcdb5-0ca2-4598-8903-863d7a29467e"), r.getResultId());
    assertEquals(59999L, r.getWindowTimestamp().getMillis());

    Violation v = r.toViolation();
    assertNotNull(v);
    assertEquals("request_threshold_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
  }

  @Test
  public void testResultFromJSONBad() throws Exception {
    Result r = Result.fromJSON("{{{");
    assertNull(r);
  }

  @Test
  public void testResultUnknownType() throws Exception {
    Result r = Result.fromJSON("{\"type\":\"unknown\"}");
    assertNull(r);
  }
}
