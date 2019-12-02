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
    String expected =
        "{\"id\":\"3512062629821359815568546405119323624381468695710007296\","
            + "\"timestamp\":1574863350330,\"message\":\"requestId: c2c284c1-af50-457c-a0f8-5116dc789211, "
            + "ip: 54.68.203.164, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /sub/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}";

    ArrayList<String> buf = new ArrayList<>();
    buf.add(
        "{\"messageType\": \"DATA_MESSAGE\", \"owner\": \"903937621340\","
            + "\"logGroup\": \"/aws/api-gateway/fxa-prod\", \"logStream\": \"a0590fb0feea74476b5c8dde497ec695\","
            + "\"subscriptionFilters\": [\"LambdaStream_lambda-to-sns\"], \"logEvents\": ["
            + "{\"id\": \"3512062629821359815568546405119323624381468695710007296\","
            + "\"timestamp\": 1574863350330,\"message\": \"requestId: c2c284c1-af50-457c-a0f8-5116dc789211, "
            + "ip: 54.68.203.164, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /sub/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}]}");
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testMultipleLogEvents() throws Exception {
    String expected1 =
        "{\"id\":\"3512062629821359815568546405119323624381468695710007296\","
            + "\"timestamp\":1574863350330,\"message\":\"requestId: c2c284c1-af50-457c-a0f8-5116dc789211, "
            + "ip: 54.68.203.164, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /sub/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}";

    String expected2 =
        "{\"id\":\"3612062629821359815568546405119323624381468695710007296\","
            + "\"timestamp\":1574863350331,\"message\":\"requestId: d2d284c1-af50-457c-a0f8-5116dc789211, "
            + "ip: 54.68.203.164, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /sub/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}";

    ArrayList<String> buf = new ArrayList<>();
    buf.add(
        "{\"messageType\": \"DATA_MESSAGE\", \"owner\": \"903937621340\","
            + "\"logGroup\": \"/aws/api-gateway/fxa-prod\", \"logStream\": \"a0590fb0feea74476b5c8dde497ec695\","
            + "\"subscriptionFilters\": [\"LambdaStream_lambda-to-sns\"], \"logEvents\": ["
            + "{\"id\": \"3512062629821359815568546405119323624381468695710007296\","
            + "\"timestamp\": 1574863350330,\"message\": \"requestId: c2c284c1-af50-457c-a0f8-5116dc789211, "
            + "ip: 54.68.203.164, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /sub/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"},"
            + "{\"id\": \"3612062629821359815568546405119323624381468695710007296\","
            + "\"timestamp\": 1574863350331,\"message\": \"requestId: d2d284c1-af50-457c-a0f8-5116dc789211, "
            + "ip: 54.68.203.164, caller: -, user: -, requestTime: 27/Nov/2019:14:02:30 +0000, "
            + "httpMethod: DELETE, resourcePath: /sub/{proxy+}, status: 404, protocol: HTTP/1.1, responseLength: 43\"}]}");
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).containsInAnyOrder(expected1, expected2);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testFilterControlMessages() {
    ArrayList<String> buf = new ArrayList<>();
    buf.add(
        "{\"messageType\": \"CONTROL_MESSAGE\", \"owner\": \"903937621340\","
            + "\"logGroup\": \"/aws/api-gateway/fxa-prod\", \"logStream\": \"a0590fb0feea74476b5c8dde497ec695\","
            + "\"subscriptionFilters\": [\"LambdaStream_lambda-to-sns\"], \"logEvents\": []}");
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new CloudWatchLogTransform());
    PAssert.that(output).empty();
    pipeline.run().waitUntilFinish();
  }
}
