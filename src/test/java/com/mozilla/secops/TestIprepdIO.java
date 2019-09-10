package com.mozilla.secops;

import static org.junit.Assert.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import java.io.IOException;
import java.io.Serializable;
import java.util.StringJoiner;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Rule;
import org.junit.Test;

public class TestIprepdIO implements Serializable {
  private static final long serialVersionUID = 1L;

  public TestIprepdIO() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  public static void putReputation(String type, String object, Integer reputation)
      throws IOException {
    HttpClient httpClient = HttpClientBuilder.create().build();

    IprepdIO.ReputationValue repValue = new IprepdIO.ReputationValue();
    repValue.setObject(object);
    repValue.setType(type);
    repValue.setReputation(reputation);
    ObjectMapper mapper = new ObjectMapper();
    String buf;
    try {
      buf = mapper.writeValueAsString(repValue);
    } catch (JsonProcessingException exc) {
      throw new IOException(exc.getMessage());
    }
    StringEntity body = new StringEntity(buf);

    String reqPath =
        new StringJoiner("/")
            .add("http://127.0.0.1:8080")
            .add("type")
            .add(type)
            .add(object)
            .toString();
    HttpPut put = new HttpPut(reqPath);
    put.setEntity(body);
    put.addHeader("Authorization", "APIKey test");
    put.addHeader("Content-Type", "application/json");
    HttpResponse resp = httpClient.execute(put);
    if (resp.getStatusLine().getStatusCode() != 200) {
      throw new IOException(
          String.format(
              "reputation put returned status code %d", resp.getStatusLine().getStatusCode()));
    }
  }

  public static void deleteReputation(String type, String object) throws IOException {
    HttpClient httpClient = HttpClientBuilder.create().build();

    String reqPath =
        new StringJoiner("/")
            .add("http://127.0.0.1:8080")
            .add("type")
            .add(type)
            .add(object)
            .toString();
    HttpDelete delete = new HttpDelete(reqPath);
    delete.addHeader("Authorization", "APIKey test");
    HttpResponse resp = httpClient.execute(delete);
    if (resp.getStatusLine().getStatusCode() != 200) {
      throw new IOException(
          String.format(
              "reputation delete returned status code %d", resp.getStatusLine().getStatusCode()));
    }
  }

  @Test
  public void iprepdIOTestWrite() throws Exception {
    IOOptions options = PipelineOptionsFactory.as(IOOptions.class);
    options.setMonitoredResourceIndicator("test");
    options.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});

    deleteReputation("ip", "127.0.0.1");
    deleteReputation("ip", "99.99.99.1");
    deleteReputation("email", "nonexistent@mozilla.com");
    deleteReputation("email", "testiprepdio1@mozilla.com");

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);

    TestUtil.getTestInput("/testdata/iprepdio1.txt", p)
        .apply(
            ParDo.of(
                new DoFn<String, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    c.output(Alert.fromJSON(c.element()));
                  }
                }))
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(OutputOptions.compositeOutput(options));

    assertEquals(100, (int) r.getReputation("ip", "127.0.0.1"));
    assertEquals(100, (int) r.getReputation("ip", "99.99.99.1"));
    assertEquals(100, (int) r.getReputation("email", "nonexistent@mozilla.com"));
    assertEquals(100, (int) r.getReputation("email", "testiprepdio1@mozilla.com"));

    p.run().waitUntilFinish();

    assertEquals(100, (int) r.getReputation("ip", "127.0.0.1"));
    assertEquals(50, (int) r.getReputation("ip", "99.99.99.1"));
    assertEquals(100, (int) r.getReputation("email", "nonexistent@mozilla.com"));
    assertEquals(0, (int) r.getReputation("email", "testiprepdio1@mozilla.com"));
  }

  @Test
  public void iprepdIOTestWriteMalformed() throws Exception {
    IOOptions options = PipelineOptionsFactory.as(IOOptions.class);
    options.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});
    options.setMonitoredResourceIndicator("test");

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);

    TestUtil.getTestInput("/testdata/iprepdio2.txt", p)
        .apply(
            ParDo.of(
                new DoFn<String, Alert>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    c.output(Alert.fromJSON(c.element()));
                  }
                }))
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(OutputOptions.compositeOutput(options));

    p.run().waitUntilFinish();

    assertEquals(100, (int) r.getReputation("ip", "1.23.xx.1"));
    assertEquals(100, (int) r.getReputation("ip", "testipr{epdio2@mozilla.com"));
  }

  @Test
  public void iprepdIOTestRead() throws Exception {
    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);

    assertEquals(100, (int) r.getReputation("ip", "127.0.0.1"));
    assertEquals(100, (int) r.getReputation("ip", "255.255.200.1"));
    putReputation("ip", "255.255.200.1", 50);
    assertEquals(50, (int) r.getReputation("ip", "255.255.200.1"));

    assertEquals(100, (int) r.getReputation("email", "sisko@mozilla.com"));
    putReputation("email", "sisko@mozilla.com", 0);
    assertEquals(0, (int) r.getReputation("email", "sisko@mozilla.com"));

    // Failed request should return 100
    r = IprepdIO.getReader("http://127.0.0.1:8081|test", null);
    assertEquals(100, (int) r.getReputation("ip", "127.0.0.1"));

    // Credential failure should return 100, use a previously submitted address
    r = IprepdIO.getReader("http://127.0.0.1:8080|invalid", null);
    assertEquals(100, (int) r.getReputation("ip", "255.255.200.1"));
  }
}
