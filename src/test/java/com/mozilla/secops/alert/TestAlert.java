package com.mozilla.secops.alert;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
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
            + "\"metadata\":{\"template_name_email\":\"test.fthl\"}}";

    Alert a = new Alert();
    assertNotNull(a);

    a.setSummary("test alert");
    a.setCategory("test");
    UUID u = UUID.fromString("d14277bb-8d69-4cd8-b83d-3ccdaf17c7b9");
    a.setAlertId(u);
    a.setEmailTemplate("test.fthl");
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
            + "\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":{\"key1\":\"another value\",\"key\":\"value\"}}";
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
  public void violationToJsonTest() throws Exception {
    String expect =
        "{\"object\":\"10.0.0.2\",\"type\":\"ip\",\"violation\":\"request_threshold_vio"
            + "lation\",\"ip\":\"10.0.0.2\"}";
    Violation v = new Violation("10.0.0.2", "ip", "request_threshold_violation");
    assertEquals(expect, v.toJSON());

    expect =
        "{\"object\":\"riker@mozilla.com\",\"type\":\"email\",\"violation\":\"abusive_account_vio"
            + "lation\"}";
    v = new Violation("riker@mozilla.com", "email", "abusive_account_violation");
    assertEquals(expect, v.toJSON());
  }

  @Test
  public void alertToAbusiveAccountViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"8c55dbae-b11f-467c-a2f6-5eafd8244cc1\",\"su"
            + "mmary\":\"test suspicious account creation, 216.160.83.56 3\",\"category\":\""
            + "customs\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":{\"notify_merge\":\"account_creation_abuse\","
            + "\"customs_category\":\"account_creation_abuse\",\"sourceaddress\":\"216.160.83.56\",\"count\":\"3\",\"email\":\"user@mail.com, user.1@mail.com, user.1.@mail.com\"}}";
    Alert a = Alert.fromJSON(buf);
    assertEquals("customs", a.getCategory());
    assertEquals("account_creation_abuse", a.getMetadataValue("customs_category"));
    assertEquals("user@mail.com, user.1@mail.com, user.1.@mail.com", a.getMetadataValue("email"));
    Violation[] v = Violation.fromAlert(a);
    assertEquals(3, v.length);
    for (Violation i : v) {
      assertThat(
          i.getObject(),
          anyOf(equalTo("user@mail.com"), equalTo("user.1@mail.com"), equalTo("user.1.@mail.com")));
      assertEquals("email", i.getType());
      // Source address compatibility field should be null for non-IP type
      assertNull(i.getSourceAddress());
    }
  }

  @Test
  public void alertToErrorRateViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"ebf9ec46-4137-416a-8b22-583f90a941ea\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:38:39.582Z\",\"metadata\":{\"category\":\"error_rate\","
            + "\"sourceaddress\":\"10.0.0.2\",\"error_count\":\"60\",\"error_threshold\":\"30\",\"window_timestamp\":\"1970-01-01T00:05:59.999Z\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("error_rate", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("30", a.getMetadataValue("error_threshold"));
    assertEquals("60", a.getMetadataValue("error_count"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("client_error_rate_violation", v.getViolation());
    // Source address should contain the same value as the object for IP type violations
    // to maintain compatibility with older versions of iprepd
    assertEquals("10.0.0.2", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("10.0.0.2", v.getObject());
  }

  @Test
  public void alertToUserAgentBlacklistViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":{\"category\":\"useragent_blacklist\","
            + "\"sourceaddress\":\"10.0.0.2\",\"window_timestamp\":\"1970-01-01T00:05:59.999Z\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("useragent_blacklist", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("useragent_blacklist_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("10.0.0.2", v.getObject());
  }

  @Test
  public void alertToThresholdViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":{\"category\":\"threshold_analysis\","
            + "\"sourceaddress\":\"10.0.0.2\",\"mean\":\"180.0\",\"count\":\"900\",\"threshold_modifier\":\"1.0\",\"window_times"
            + "tamp\":\"1970-01-01T00:05:59.999Z\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("threshold_analysis", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("180.0", a.getMetadataValue("mean"));
    assertEquals("900", a.getMetadataValue("count"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("request_threshold_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("10.0.0.2", v.getObject());
  }

  @Test
  public void alertToAmoNewVersionLoginEndpointAbuseViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"64d03714-9d49-4269-a341-4be55145fb4d\",\"summ"
            + "ary\":\"test login to amo from suspected fraudulent account, kurn@mozilla.com"
            + " from 216.160.83.56\",\"category\":\"amo\",\"timestamp\":\"2019-06-24T19:04:41"
            + ".507Z\",\"metadata\":{\"notify_merge\":\"fxa_account_abuse_new_version_login\","
            + "\"sourceaddress\":\"216.160.83.56\",\"email\":\"kurn@mozilla.com\","
            + "\"amo_category\":\"fxa_account_abuse_new_version_login\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("fxa_account_abuse_new_version_login", a.getMetadataValue("amo_category"));
    assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("endpoint_abuse_violation", v.getViolation());
    assertEquals("216.160.83.56", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("216.160.83.56", v.getObject());
    assertNull(v.getSuppressRecovery());
  }

  @Test
  public void alertToAmoAddonMatchViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"e056ef7b-5b02-40d7-a7da-b3b5c866144c\",\"summ"
            + "ary\":\"test suspected malicious addon submission from 216.160.83.63, lwaxana"
            + "@mozilla.com\",\"category\":\"amo\",\"timestamp\":\"2019-07-11T17:47:52.915Z"
            + "\",\"metadata\":{\"notify_merge\":\"amo_abuse_matched_addon\","
            + "\"amo_category\":\"amo_abuse_matched_addon\",\"sourceaddress\":\"216.160.83.63\","
            + "\"email\":\"lwaxana@mozilla.com, lwaxana@mozilla.com, lwaxana@mozilla.com\","
            + "\"addon_filename\":\"00000000000000000000000000000000_test_submission.zip\","
            + "\"addon_size\":\"7500\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("amo_abuse_matched_addon", a.getMetadataValue("amo_category"));
    assertEquals("216.160.83.63", a.getMetadataValue("sourceaddress"));
    assertEquals(
        "lwaxana@mozilla.com, lwaxana@mozilla.com, lwaxana@mozilla.com",
        a.getMetadataValue("email"));
    Violation[] v = Violation.fromAlert(a);
    // We should have 4 here, 1 for the source address, 1 for the email address, and 2
    // additional violations for the normalized email components (which in this case will
    // be identical
    assertEquals(4, v.length);
    for (Violation i : v) {
      if (i.getType().equals("email")) {
        assertEquals("lwaxana@mozilla.com", i.getObject());
        assertEquals("abusive_account_violation", i.getViolation());
      } else {
        assertEquals("ip", i.getType());
        assertEquals("216.160.83.63", i.getObject());
        assertEquals("endpoint_abuse_violation", i.getViolation());
      }
    }
  }

  @Test
  public void alertToAmoAddonMultiMatchTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"5e6d23b2-59c9-4ffb-8194-7a714919afe7\",\"summ"
            + "ary\":\"test addon abuse multi match, 5\",\"category\":\"amo\",\"timestamp\":"
            + "\"2019-07-11T20:28:29.262Z\",\"metadata\":{\"notify_merge\":\"amo_abuse_multi_match\","
            + "\"amo_category\":\"amo_abuse_multi_match\",\"email\":\"ro5@mozilla.com, ro1@mozilla"
            + ".com, ro2@mozilla.com, ro3@mozilla.com, ro4@mozilla.com\",\"count"
            + "\":\"5\",\"addon_filename\":\"x.xpi\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("amo_abuse_multi_match", a.getMetadataValue("amo_category"));
    assertEquals("5", a.getMetadataValue("count"));
    Violation[] v = Violation.fromAlert(a);
    assertEquals(5, v.length);
    assertEquals("abusive_account_violation", v[0].getViolation());
    assertEquals("email", v[0].getType());
  }

  @Test
  public void alertToAmoMultiSubmitTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"169f5030-22db-4849-8421-75462b986a98\",\"summar"
            + "y\":\"test addon abuse multi submit, 10000 11\",\"category\":\"amo\",\"timestam"
            + "p\":\"2019-07-18T20:04:58.299Z\",\"metadata\":{\"notify_merge\":\"amo_abuse_multi_submit\","
            + "\"amo_category\":\"amo_abuse_multi_submit\",\"email\":\"ro10@mozilla.com, ro9@mozilla.c"
            + "om, ro5@mozilla.com, ro6@mozilla.com, ro1@mozilla.com, ro2@mozilla.com, ro4@moz"
            + "illa.com, lwaxana@mozilla.com, ro7@mozilla.com, ro8@mozilla.com, ro3@mozilla.com"
            + "\",\"count\":\"11\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("amo_abuse_multi_submit", a.getMetadataValue("amo_category"));
    assertEquals("11", a.getMetadataValue("count"));
    Violation[] v = Violation.fromAlert(a);
    assertEquals(11, v.length);
    assertEquals("abusive_account_violation", v[0].getViolation());
    assertEquals("email", v[0].getType());
  }

  @Test
  public void alertToAmoMultiIpLoginTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"e131a5c0-ae88-4676-9fa9-472fabb45d68\",\"summar"
            + "y\":\"test addon abuse multi ip country login, sevenofnine@mozilla.net 2 countr"
            + "ies, 2 source address\",\"category\":\"amo\",\"timestamp\":\"2019-07-18T20:09:0"
            + "2.973Z\",\"metadata\":{\"notify_merge\":\"amo_abuse_multi_ip_login\","
            + "\"amo_category\":\"amo_abuse_multi_ip_login\",\"email\":\"sevenofnine@mozilla.net\",\"count\":\"2\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("amo_abuse_multi_ip_login", a.getMetadataValue("amo_category"));
    assertEquals("2", a.getMetadataValue("count"));
    Violation[] v = Violation.fromAlert(a);
    assertEquals(1, v.length);
    assertEquals("abusive_account_violation", v[0].getViolation());
    assertEquals("email", v[0].getType());
    assertEquals("sevenofnine@mozilla.net", v[0].getObject());
  }

  @Test
  public void alertToAmoAliasAbuseTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"8e1f668b-4fd5-46f8-ad6f-255d5b9b9729\",\"summar"
            + "y\":\"test possible alias abuse in amo, laforge@mozilla.com has 6 aliases\",\"c"
            + "ategory\":\"amo\",\"timestamp\":\"2019-07-18T20:09:02.987Z\",\"metadata\":{\"notify_merge\":\"fxa_account_abuse_alias\","
            + "\"amo_category\":\"fxa_account_abuse_alias\",\"email\":\"l"
            + "aforge@mozilla.com, laforge+test1@mozilla.com, laforge+test2@mozilla.com, lafor"
            + "ge+test3@mozilla.com, laforge+test4@mozilla.com, laforge+test5@mozilla.com, laf"
            + "orge+test6@mozilla.com\",\"count\":\"6\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("fxa_account_abuse_alias", a.getMetadataValue("amo_category"));
    assertEquals("6", a.getMetadataValue("count"));
    Violation[] v = Violation.fromAlert(a);
    assertEquals(7, v.length); // Should have one extra violation for the normalized version
    assertEquals("abusive_account_violation", v[0].getViolation());
    assertEquals("email", v[0].getType());
  }

  @Test
  public void alertToAmoNewVersionLoginBanPatternTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"64d03714-9d49-4269-a341-4be55145fb4d\",\"summ"
            + "ary\":\"test login to amo from suspected fraudulent account, kurn@mozilla.com"
            + " from 216.160.83.56\",\"category\":\"amo\",\"timestamp\":\"2019-06-24T19:04:41"
            + ".507Z\",\"metadata\":{\"notify_merge\":\"fxa_account_abuse_new_version_login_banpattern\","
            + "\"sourceaddress\":\"216.160.83.56\",\"email\":\"kurn@mozilla.com\",\"amo_category\":\"fxa_account_abuse_new_version_login_banpattern\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals(
        "fxa_account_abuse_new_version_login_banpattern", a.getMetadataValue("amo_category"));
    assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("abusive_account_violation", v.getViolation());
    assertEquals("email", v.getType());
    assertEquals("kurn@mozilla.com", v.getObject());
    assertNull(v.getSuppressRecovery());
  }

  @Test
  public void alertToAmoNewVersionSubmissionEndpointAbuseViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"d18cfcaa-8f72-48db-9ec6-5cbcb0225fb6\",\"summ"
            + "ary\":\"test addon submission from address associated with suspected fraudule"
            + "nt account, 216.160.83.56\",\"category\":\"amo\",\"timestamp\":\"2019-06-24T1"
            + "9:09:20.749Z\",\"metadata\": {\"notify_merge\":\"fxa_account_abuse_new_version_submission\","
            + "\"sourceaddress\":\"216.160.83.56\",\"amo_category\":\"fxa_account_abuse_new_version_submission\","
            + "\"addon_id\":\"0000001\",\"addon_version\":\"1.0.0\"}}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("amo", a.getCategory());
    assertEquals("fxa_account_abuse_new_version_submission", a.getMetadataValue("amo_category"));
    assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("endpoint_abuse_violation", v.getViolation());
    assertEquals("216.160.83.56", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("216.160.83.56", v.getObject());
    assertNull(v.getSuppressRecovery());
  }

  @Test
  public void alertToEndpointAbuseViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":{\"category\":\"endpoint_abuse\","
            + "\"sourceaddress\":\"10.0.0.2\",\"endpoint\":\"/test\",\"count\":\"900\","
            + "\"method\":\"POST\",\"window_timestamp\":\"1970-01-01T00:05:59.999Z\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("endpoint_abuse", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("/test", a.getMetadataValue("endpoint"));
    assertEquals("900", a.getMetadataValue("count"));
    assertNull(a.getMetadataValue("iprepd_suppress_recovery"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("endpoint_abuse_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("10.0.0.2", v.getObject());
    assertNull(v.getSuppressRecovery());
  }

  @Test
  public void alertToEndpointAbuseViolationSuppressTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":{\"category\":\"endpoint_abuse\","
            + "\"sourceaddress\":\"10.0.0.2\",\"endpoint\":\"/test\",\"count\":\"900\","
            + "\"method\":\"POST\",\"window_timestamp\":\"1970-01-01T00:05:59.999Z\",\"iprepd_suppress_recovery\":\"60\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("endpoint_abuse", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("/test", a.getMetadataValue("endpoint"));
    assertEquals("900", a.getMetadataValue("count"));
    assertEquals("60", a.getMetadataValue("iprepd_suppress_recovery"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("endpoint_abuse_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("10.0.0.2", v.getObject());
    assertEquals(60, (int) v.getSuppressRecovery());
  }

  @Test
  public void alertToHardLimitViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":{\"category\":\"hard_limit\","
            + "\"sourceaddress\":\"10.0.0.2\",\"count\":\"900\",\"window_timestamp\":\"1970-01-01T00:05:59.999Z\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("hard_limit", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("900", a.getMetadataValue("count"));
    assertEquals(1, Violation.fromAlert(a).length);
    Violation v = Violation.fromAlert(a)[0];
    assertNotNull(v);
    assertEquals("hard_limit_violation", v.getViolation());
    assertEquals("10.0.0.2", v.getSourceAddress());
    assertEquals("ip", v.getType());
    assertEquals("10.0.0.2", v.getObject());
  }

  @Test
  public void alertToUnknownViolationTest() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"620171b5-6597-48a7-94c2-006cc2b83c96\",\"category\""
            + ":\"httprequest\",\"timestamp\":\"2019-01-09T19:47:37.600Z\",\"metadata\":{\"category\":\"unknown\","
            + "\"sourceaddress\":\"10.0.0.2\",\"mean\":\"180.0\",\"count\":\"900\","
            + "\"threshold_modifier\":\"1.0\",\"window_timestamp\":\"1970-01-01T00:05:59.999Z\"}}";
    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    assertEquals("httprequest", a.getCategory());
    assertEquals("unknown", a.getMetadataValue("category"));
    assertEquals("10.0.0.2", a.getMetadataValue("sourceaddress"));
    assertEquals("180.0", a.getMetadataValue("mean"));
    assertEquals("900", a.getMetadataValue("count"));
    Violation[] v = Violation.fromAlert(a);
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
