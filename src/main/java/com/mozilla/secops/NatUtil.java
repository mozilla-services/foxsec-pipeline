package com.mozilla.secops;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NatUtil {

  private static final Logger log = LoggerFactory.getLogger(NatUtil.class);

  /**
   * Load detect nat manager configuration from a resource file
   *
   * @param path Path to load file file from, resource path or GCS URL
   * @return a map containing each ip and the value true
   */
  public static Map<String, Boolean> loadGatewayList(String path) {
    HashMap<String, Boolean> gateways = new HashMap<String, Boolean>();
    InputStream in;
    if (path == null || path.isEmpty()) {
      log.info("No initial nat gateway list given, using empty list.");
      return gateways;
    }
    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = NatUtil.class.getResourceAsStream(path);
    }
    if (in == null) {
      log.error("Unable to read nat gateway list: {}", path);
      return gateways;
    }
    BufferedReader r = new BufferedReader(new InputStreamReader(in));
    try {
      while (r.ready()) {
        gateways.put(r.readLine(), true);
      }
      r.close();
    } catch (IOException e) {
      log.error("Error reading nat gateway list: {}", e.getMessage());
    }
    return gateways;
  }
}
