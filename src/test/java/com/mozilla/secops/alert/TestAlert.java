package com.mozilla.secops.alert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

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
  public void alertToJsonTest() throws Exception {
    String expect =
        "{\"severity\":\"info\",\"id\":\"d14277bb-8d69-4cd8-b83d-3ccdaf17c7b9\","
            + "\"summary\":\"test alert\""
            + ",\"category\":\"test\",\"payload\":\"first line\\n\\nsecond line\","
            + "\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"template_name\":\"test.fthl\"}";

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
  public void alertFromBadJson() throws Exception {
    Alert a = Alert.fromJSON("{{{");
    assertNull(a);
  }
}
