package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
import java.util.ArrayList;
import org.junit.Test;

public class TestCustomsAlert {
  @Test
  public void testAlertConversion() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"85e899ac-28fa-46d6-84c1-36c2061eed49\",\"summary"
            + "\":\"test suspicious account creation, 216.160.83.56 3\",\"category\":\"customs"
            + "\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":[{\"key\":\"notify_m"
            + "erge\",\"value\":\"account_creation_abuse\"},{\"key\":\"category\",\"va"
            + "lue\":\"account_creation_abuse\"},{\"key\":\"sourceaddress\",\"value\":\"216.16"
            + "0.83.56\"},{\"key\":\"count\",\"value\":\"3\"},{\"key\":\"email\",\"value\":\"u"
            + "ser@mail.com, user.1@mail.com, user.1.@mail.com\"}]}";
    ArrayList<CustomsAlert> c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(4, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"6f520812-7081-4e7e-9b6c-c25bf69f6744\",\"summa"
            + "ry\":\"test suspicious distributed account creation, 216.160.83.54 6\",\"categ"
            + "ory\":\"customs\",\"timestamp\":\"2019-09-16T18:13:39.390Z\",\"metadata\":[{\""
            + "key\":\"notify_merge\",\"value\":\"account_creation_abuse_distributed\"},{\"ke"
            + "y\":\"category\",\"value\":\"account_creation_abuse_distributed\"},{\""
            + "key\":\"count\",\"value\":\"6\"},{\"key\":\"sourceaddress\",\"value\":\"216.16"
            + "0.83.54\"},{\"key\":\"email\",\"value\":\"user6@mail.com\"},{\"key\":\"email_s"
            + "imilar\",\"value\":\"user3@mail.com, user1@mail.com, user2@mail.com, user4@mai"
            + "l.com, user5@mail.com\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    // We should have two here, one for the primary address indicator and one for the source
    // address.
    //
    // Since this heuristic will create an alert for each of the similar addresses too, we don't
    // expect those to be included in the returned alert list as well (those will be converted
    // as they come in, in the same way).
    assertEquals(2, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"64c95dc0-fa41-4fa4-8275-eee23d1c5ca9\",\"summary\":"
            + "\"test source login failure threshold exceeded, 216.160.83.56 10 in 300 seconds\","
            + "\"category\":\"customs\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":["
            + "{\"key\":\"notify_merge\",\"value\":\"source_login_failure\"},{\"key\":\"c"
            + "ategory\",\"value\":\"source_login_failure\"},{\"key\":\"sourceaddress\",\"value\""
            + ":\"216.160.83.56\"},{\"key\":\"count\",\"value\":\"10\"},{\"key\":\"email\",\"valu"
            + "e\":\"spock@mozilla.com\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(1, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"106fb514-f402-4d41-a07a-01c8900335d1\",\"summary\":\"t"
            + "est 10.0.0.1 attempted password reset on 5 distinct accounts in 10 minute window\",\"c"
            + "ategory\":\"customs\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":[{\"key"
            + "\":\"notify_merge\",\"value\":\"password_reset_abuse\"},{\"key\":\"category\""
            + ",\"value\":\"password_reset_abuse\"},{\"key\":\"sourceaddress\",\"value\":\"10.0.0.1"
            + "\"},{\"key\":\"count\",\"value\":\"5\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(1, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"e2737df3-b416-43e3-a082-9ebd110bc71c\",\"summary\":\"te"
            + "st distributed source login failure threshold exceeded for single account, 10 addresses"
            + " in 600 seconds\",\"category\":\"customs\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\""
            + "metadata\":[{\"key\":\"notify_merge\",\"value\":\"source_login_failure_distributed\"},{\""
            + "key\":\"category\",\"value\":\"source_login_failure_distributed\"},{\"key\":\"em"
            + "ail\",\"value\":\"kirk@mozilla.com\"},{\"key\":\"count\",\"value\":\"10\"},{\"key\":\"so"
            + "urceaddresses\",\"value\":\"10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, "
            + "10.0.0.7, 10.0.0.8, 10.0.0.9, 10.0.0.10\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(10, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"63d44a9a-e5b7-4568-a343-0acec9f2ec7c\",\"summary\":\"test "
            + "00000000000000000000000000000000 velocity exceeded, 7740.82 km in 9 seconds\",\"category\""
            + ":\"customs\",\"timestamp\":\"1970-01-01T00:00:09.000Z\",\"metadata\":[{\"key\":\"category\""
            + ",\"value\":\"velocity\"},{\"key\":\"notify_merge\",\"value\":\"velocity\"},{\"key\":\"sourc"
            + "eaddress\",\"value\":\"81.2.69.192\"},{\"key\":\"sourceaddress_previous\",\"value\":\"216.1"
            + "60.83.56\"},{\"key\":\"time_delta_seconds\",\"value\":\"9\"},{\"key\":\"km_distance\",\"val"
            + "ue\":\"7740.82\"},{\"key\":\"uid\",\"value\":\"00000000000000000000000000000000\"},{\"key\""
            + ":\"email\",\"value\":\"riker@mozilla.com\"},{\"key\":\"sourceaddress_city\",\"value\":\"Lon"
            + "don\"},{\"key\":\"sourceaddress_country\",\"value\":\"GB\"},{\"key\":\"sourceaddress_previo"
            + "us_city\",\"value\":\"Milton\"},{\"key\":\"sourceaddress_previous_country\",\"value\":\"US\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(2, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"9b38ee45-09c3-4497-a04f-d1190c7a7c24\",\"summary\":\"test stat"
            + "us check comparator indicates known address\",\"category\":\"customs\",\"timestamp\":\"2020-06"
            + "-04T23:48:37.282Z\",\"metadata\":[{\"key\":\"category\",\"value\":\"status_comparator\"},{\"ke"
            + "y\":\"notify_merge\",\"value\":\"status_comparator\"},{\"key\":\"email\",\"value\":\"spock@moz"
            + "illa.com\"},{\"key\":\"sourceaddress\",\"value\":\"3.3.3.3\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(1, c.size());

    buf =
        "{\"severity\":\"info\",\"id\":\"c2786a21-5f6e-41ae-9942-ba723cd22447\",\"summary\":\"test login "
            + "failure for at risk account, 10.0.1.11\",\"category\":\"customs\",\"timestamp\":\"2020-06-05T20:"
            + "23:53.123Z\",\"metadata\":[{\"key\":\"category\",\"value\":\"login_failure_at_risk_account\"},"
            + "{\"key\":\"notify_merge\",\"value\":\"login_failure_at_risk_account\"},{\"key\":\"email\",\"va"
            + "lue\":\"spock@mozilla.com\"},{\"key\":\"sourceaddress\",\"value\":\"10.0.1.11\"}]}";
    c = CustomsAlert.fromAlert(Alert.fromJSON(buf));
    assertEquals(1, c.size());
  }
}
