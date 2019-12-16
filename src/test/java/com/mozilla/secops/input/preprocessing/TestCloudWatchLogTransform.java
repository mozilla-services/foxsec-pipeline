package com.mozilla.secops.input.preprocessing;

import java.util.ArrayList;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestCloudWatchLogTransform {

  @Rule public final transient TestPipeline pipeline = TestPipeline.create();

  @Test
  public void testSingleLogEvent() throws Exception {
    // If there is only one event in logEvents, the same log entry is returned
    String expected =
        "{\"messageType\":\"DATA_MESSAGE\",\"owner\":\"12345\","
            + "\"logGroup\":\"/test/group\",\"logStream\":\"123\","
            + "\"subscriptionFilters\":[\"filter\"],\"logEvents\":["
            + "{\"id\":\"123\","
            + "\"timestamp\":1574863350330,\"message\":\"requestId: 77fa2b02-99d5-42d7-b315-777fdab08e05, "
            + "ip: 10.0.0.1, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /test/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}]}";

    ArrayList<String> buf = new ArrayList<>();
    buf.add(expected);
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testMultipleLogEvents() throws Exception {
    // If there are multiple logEvents in an entry, we get multiple
    // log entries where each contains a single event in logEvents
    String expected1 =
        "{\"messageType\":\"DATA_MESSAGE\",\"owner\":\"12345\","
            + "\"logGroup\":\"/test/group\",\"logStream\":\"123\","
            + "\"subscriptionFilters\":[\"filter\"],\"logEvents\":["
            + "{\"id\":\"123\","
            + "\"timestamp\":1574863350330,\"message\":\"requestId: 77fa2b02-99d5-42d7-b315-777fdab08e05, "
            + "ip: 10.0.0.1, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /test/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}]}";

    String expected2 =
        "{\"messageType\":\"DATA_MESSAGE\",\"owner\":\"12345\","
            + "\"logGroup\":\"/test/group\",\"logStream\":\"123\","
            + "\"subscriptionFilters\":[\"filter\"],\"logEvents\":["
            + "{\"id\":\"124\","
            + "\"timestamp\":1574863350331,\"message\":\"requestId: 7185692c-0db8-473f-b900-aac759713333, "
            + "ip: 10.0.0.1, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /test/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}]}";

    ArrayList<String> buf = new ArrayList<>();
    buf.add(
        "{\"messageType\": \"DATA_MESSAGE\", \"owner\": \"12345\","
            + "\"logGroup\": \"/test/group\", \"logStream\": \"123\","
            + "\"subscriptionFilters\": [\"filter\"], \"logEvents\": ["
            + "{\"id\": \"123\","
            + "\"timestamp\": 1574863350330,\"message\": \"requestId: 77fa2b02-99d5-42d7-b315-777fdab08e05, "
            + "ip: 10.0.0.1, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /test/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"},"
            + "{\"id\": \"124\","
            + "\"timestamp\": 1574863350331,\"message\": \"requestId: 7185692c-0db8-473f-b900-aac759713333, "
            + "ip: 10.0.0.1, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /test/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}]}");
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).containsInAnyOrder(expected1, expected2);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testFilterControlMessages() {
    // We exclude non data messages as these do not have meaningful events
    ArrayList<String> buf = new ArrayList<>();
    buf.add(
        "{\"messageType\": \"CONTROL_MESSAGE\", \"owner\": \"123\","
            + "\"logGroup\": \"/test/log/grpi[\", \"logStream\": \"123\","
            + "\"subscriptionFilters\": [\"filter\"], \"logEvents\": []}");
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).empty();
    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testNonCloudWatchLogMessagesAreNotModified() {
    // Non CloudWatch logs are not modified and are passed on
    String expected = "{\"owner\": \"1234567890\"}";
    ArrayList<String> buf = new ArrayList<>();
    buf.add(expected);
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).containsInAnyOrder(expected);
    pipeline.run().waitUntilFinish();
  }
}
