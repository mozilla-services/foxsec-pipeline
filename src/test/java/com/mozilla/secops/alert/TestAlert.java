package com.mozilla.secops.alert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.mozilla.secops.Violation;
import java.util.UUID;
import org.joda.time.DateTime;
import org.junit.Test;

public class TestAlert {
  public TestAlert() {}

  @Test
  public void basicAlertTest() throws Exception {
    Alert a = new Alert();
    assertNotNull(a);
    assertNotNull(a.getAlertId());
  }

  @Test
  public void alertMergeKeyTest() throws Exception {
    Alert a = new Alert();
    assertNotNull(a);
    a.setSummary("test");
    a.setNotifyMergeKey("key");
    a = Alert.fromJSON(a.toJSON());
    assertNotNull(a);
    assertEquals("key", a.getNotifyMergeKey());
    assertEquals("key", a.getMetadataValue("notify_merge"));
  }

  @Test
  public void alertToJsonTest() throws Exception {
    String expect =
        "{\"severity\":\"info\",\"id\":\"d14277bb-8d69-4cd8-b83d-3ccdaf17c7b9\","
            + "\"summary\":\"test alert\""
            + ",\"category\":\"test\",\"payload\":\"first line\\n\\nsecond line\","
            + "\"timestamp\":\"1970-01-01T00:00:00.000Z\","
            + "\"metadata\":[{\"key\":\"template_name\",\"value\":\"test.fthl\"}]}";

    Alert a = new Alert();
    assertNotNull(a);

    a.setSummary("test alert");
    a.setCategory("test");
    UUID u = UUID.fromString("d14277bb-8d69-4cd8-b83d-3ccdaf17c7b9");
    a.setAlertId(u);
    a.setTemplateName("test.fthl");
    a.setTimestamp(new DateTime(0L));

    a.addToPayload("first line");
    a.addToPayload("");
    a.addToPayload("second line");

    assertEquals(expect, a.toJSON());
  }

  @Test
  public void alertToJsonMetadataTest() throws Exception {
    String expect =
        "{\"severity\":\"critical\",\"id\":\"d14277bb-8d69-4cd8-b83d-3ccdaf17c7b9\","
            + "\"summary\":\"test alert\","
            + "\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":[{\"key\":\"key\","
            + "\"value\":\"value\"},{\"key\":\"key1\",\"value\":\"another value\"}]}";
    Alert a = new Alert();
    assertNotNull(a);

    UUID u = UUID.fromString("d14277bb-8d69-4cd8-b83d-3ccdaf17c7b9");
    a.setAlertId(u);
    a.setTimestamp(new DateTime(0L));
    a.setSummary("test alert");
    a.setSeverity(Alert.AlertSeverity.CRITICAL);
    a.addMetadata("key", "value");
    a.addMetadata("key1", "another value");

    assertEquals(expect, a.toJSON());
  }

  @Test
  public void alertToErrorRateViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"ebf9ec46-4137-416a-8b22-583f90a941ea\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:38:39.582Z\",\"metadata\":[{\"key\""
            + ":\"category\",\"value\":\"error_rate\"},{\"key\":\"sourceaddress\",\"value\":\"10."
            + "0.0.2\"},{\"key\":\"error_count\",\"value\":\"60\"},{\"key\":\"error_threshold\","
            + "\"value\":\"30\"},{\"key\":\"window_timestamp\",\"value\":\"1970-01-01T00:05:59.999Z\"}]}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("error_rate", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("30", a.getMetadataValue("error_threshold"));
    assertEquals("60", a.getMetadataValue("error_count"));
    Violation v = Violation.fromAlert(a);
    assertNotNull(v);
    assertEquals("client_error_rate_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
  }

  @Test
  public void alertToThresholdViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":[{\"key\":"
            + "\"category\",\"value\":\"threshold_analysis\"},{\"key\":\"sourceaddress\",\"value\""
            + ":\"10.0.0.2\"},{\"key\":\"mean\",\"value\":\"180.0\"},{\"key\":\"count\",\"value\":"
            + "\"900\"},{\"key\":\"threshold_modifier\",\"value\":\"1.0\"},{\"key\":\"window_times"
            + "tamp\",\"value\":\"1970-01-01T00:05:59.999Z\"}]}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("threshold_analysis", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("180.0", a.getMetadataValue("mean"));
    assertEquals("900", a.getMetadataValue("count"));
    Violation v = Violation.fromAlert(a);
    assertNotNull(v);
    assertEquals("request_threshold_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
  }

  @Test
  public void alertToEndpointAbuseViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":[{\"key\":"
            + "\"category\",\"value\":\"endpoint_abuse\"},{\"key\":\"sourceaddress\",\"value\""
            + ":\"10.0.0.2\"},{\"key\":\"endpoint\",\"value\":\"/test\"},{\"key\":\"count\",\"value\":"
            + "\"900\"},{\"key\":\"method\",\"value\":\"POST\"},{\"key\":\"window_times"
            + "tamp\",\"value\":\"1970-01-01T00:05:59.999Z\"}]}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("endpoint_abuse", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("/test", a.getMetadataValue("endpoint"));
    assertEquals("900", a.getMetadataValue("count"));
    Violation v = Violation.fromAlert(a);
    assertNotNull(v);
    assertEquals("endpoint_abuse_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
  }

  @Test
  public void alertToUnknownViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":[{\"key\":"
            + "\"category\",\"value\":\"unknown\"},{\"key\":\"sourceaddress\",\"value\""
            + ":\"10.0.0.2\"},{\"key\":\"mean\",\"value\":\"180.0\"},{\"key\":\"count\",\"value\":"
            + "\"900\"},{\"key\":\"threshold_modifier\",\"value\":\"1.0\"},{\"key\":\"window_times"
            + "tamp\",\"value\":\"1970-01-01T00:05:59.999Z\"}]}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("unknown", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("180.0", a.getMetadataValue("mean"));
    assertEquals("900", a.getMetadataValue("count"));
    Violation v = Violation.fromAlert(a);
    assertNull(v);
  }

  @Test
  public void alertFromBadJson() throws Exception {
    Alert a = Alert.fromJSON("{{{");
    assertNull(a);
  }

  @Test
  public void testCorrectFields() throws Exception {
    Alert a = new Alert();
    assertNotNull(a);
    assertFalse(a.hasCorrectFields());
    a.setSummary("test alert");
    assertTrue(a.hasCorrectFields());
  }
}
