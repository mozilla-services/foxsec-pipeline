package com.mozilla.secops;

import static org.junit.Assert.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.StringJoiner;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Test;

public class TestIprepdIO {
  public TestIprepdIO() {}

  public void putReputation(String type, String object, Integer reputation) throws IOException {
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

  @Test
  public void iprepdIOTestRead() throws Exception {
    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080", "test", null);

    assertEquals(100, (int) r.getReputation("ip", "127.0.0.1"));
    assertEquals(100, (int) r.getReputation("ip", "255.255.200.1"));
    putReputation("ip", "255.255.200.1", 50);
    assertEquals(50, (int) r.getReputation("ip", "255.255.200.1"));

    assertEquals(100, (int) r.getReputation("email", "sisko@mozilla.com"));
    putReputation("email", "sisko@mozilla.com", 0);
    assertEquals(0, (int) r.getReputation("email", "sisko@mozilla.com"));

    // Failed request should return 100
    r = IprepdIO.getReader("http://127.0.0.1:8081", "test", null);
    assertEquals(100, (int) r.getReputation("ip", "127.0.0.1"));

    // Credential failure should return 100, use a previously submitted address
    r = IprepdIO.getReader("http://127.0.0.1:8080", "invalid", null);
    assertEquals(100, (int) r.getReputation("ip", "255.255.200.1"));
  }
}
