package com.mozilla.secops.httprequest;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.GcsUtil;
import com.mozilla.secops.input.Input;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;

/** HTTPRequest multimode configuration */
@JsonInclude(Include.NON_EMPTY)
public class HTTPRequestMultiMode {
  private Input input;
  private HashMap<String, HTTPRequestToggles> serviceToggles;

  /**
   * Load multimode configuration from GCS or as a resource
   *
   * @param path Path to load JSON file from, resource path or GCS URL
   * @return {@link HTTPRequestMultiMode}
   * @throws IOException IOException
   */
  public static HTTPRequestMultiMode load(String path) throws IOException {
    InputStream in;
    if (path == null) {
      throw new IOException("attempt to load multimode configuration with null path");
    }
    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = HTTPRequestMultiMode.class.getResourceAsStream(path);
    }
    if (in == null) {
      throw new IOException("multimode configuration resource not found");
    }
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue(in, HTTPRequestMultiMode.class);
  }

  /**
   * Set input configuration
   *
   * @param input Input
   */
  @JsonProperty("input")
  public void setInput(Input input) {
    this.input = input;
  }

  /**
   * Get input configuration
   *
   * @return Input
   */
  public Input getInput() {
    return input;
  }

  /**
   * Set service toggles
   *
   * @param serviceToggles Map of service/HTTPRequestToggles
   */
  @JsonProperty("service_toggles")
  public void setServiceToggles(HashMap<String, HTTPRequestToggles> serviceToggles) {
    this.serviceToggles = serviceToggles;
  }

  /**
   * Get service toggles
   *
   * @return Map of service/HTTPRequestToggles
   */
  public HashMap<String, HTTPRequestToggles> getServiceToggles() {
    return serviceToggles;
  }
}
