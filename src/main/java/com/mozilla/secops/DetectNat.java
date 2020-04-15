package com.mozilla.secops;

import com.google.common.annotations.VisibleForTesting;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.apache.beam.sdk.values.TypeDescriptors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides NAT detection transforms
 *
 * <p>Currently this transform only operates on normalized {@link
 * com.mozilla.secops.parser.Normalized.Type#HTTP_REQUEST} events and is based on the detection of
 * multiple user agents being identified for requests within the window for the same source IP
 * address.
 *
 * <p>The output from the transform is a {@link PCollection} of KV pairs where the key is a source
 * IP address identified in the window and the value is a boolean set to true if there is a
 * possibility the source address is a NAT gateway. If it is not suspected the source address is a
 * NAT gateway, it will not be included in the output set.
 */
public class DetectNat {

  private static final Logger log = LoggerFactory.getLogger(DetectNat.class);

  /**
   * Return an empty NAT view, suitable as a placeholder if NAT detection is not desired
   *
   * @param p Pipeline to create view for
   * @return Empty {@link PCollectionView}
   */
  public static PCollectionView<Map<String, Boolean>> getEmptyView(Pipeline p) {
    return p.apply(
            "empty nat view",
            Create.empty(
                TypeDescriptors.kvs(TypeDescriptors.strings(), TypeDescriptors.booleans())))
        .apply(View.<String, Boolean>asMap());
  }

  /**
   * Execute nat detection transforms returning a {@link PCollectionView} suitable for use as a side
   * input, currently only User Agent Based
   *
   * @param events Input events
   * @param knownGatewaysPath path to file with known gateway ip addresses
   * @return {@link PCollectionView} representing output of analysis
   */
  public static PCollectionView<Map<String, Boolean>> getView(
      PCollection<Event> events, String knownGatewaysPath) {
    return events
        .apply("nat view", byUserAgent().withKnownGateways(knownGatewaysPath))
        .apply(View.<String, Boolean>asMap());
  }

  /**
   * Provides a basic NAT detection transform
   *
   * <p>Currently this transform only operates on normalized {@link
   * com.mozilla.secops.parser.Normalized.Type#HTTP_REQUEST} events and is based on the detection of
   * multiple user agents being identified for requests within the window for the same source IP
   * address.
   *
   * <p>The output from the transform is a {@link PCollection} of KV pairs where the key is a source
   * IP address identified in the window and the value is a boolean set to true if there is a
   * possibility the source address is a NAT gateway. If it is not suspected the source address is a
   * NAT gateway, it will not be included in the output set.
   */
  public static class UserAgentBased
      extends PTransform<PCollection<Event>, PCollection<KV<String, Boolean>>> {
    private static final long serialVersionUID = 1L;
    private static final Long UAMARKPROBABLE = 2L;
    private Map<String, Boolean> knownGateways;
    private String knownGatewaysPath;

    private UserAgentBased(Map<String, Boolean> knownGateways) {
      this.knownGateways = knownGateways;
    }

    private UserAgentBased(String path) {
      this.knownGatewaysPath = path;
    }

    @Override
    public PCollection<KV<String, Boolean>> expand(PCollection<Event> events) {
      PCollection<KV<String, Long>> perSourceUACounts =
          events
              .apply(
                  "detectnat extract user agents",
                  ParDo.of(
                      new DoFn<Event, KV<String, String>>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c) {
                          Event e = c.element();

                          Normalized n = e.getNormalized();
                          if (n.isOfType(Normalized.Type.HTTP_REQUEST)) {
                            if (n.getSourceAddress() != null && n.getUserAgent() != null) {
                              c.output(KV.of(n.getSourceAddress(), n.getUserAgent()));
                            }
                          } else {
                            return;
                          }
                        }
                      }))
              .apply("detectnat distinct ua map", Distinct.<KV<String, String>>create())
              .apply("detectnat ua count per key", Count.<String, String>perKey());

      // Operate solely on the UA output right now here, but this should be expanded with more
      // detailed analysis
      return perSourceUACounts.apply(
          "detect nat",
          ParDo.of(
              new DoFn<KV<String, Long>, KV<String, Boolean>>() {
                private static final long serialVersionUID = 1L;

                @Setup
                public void setup() {
                  if (knownGateways.size() == 0 && knownGatewaysPath != null) {
                    knownGateways = loadGatewayList(knownGatewaysPath);
                  }
                }

                @ProcessElement
                public void processElement(ProcessContext c) {
                  KV<String, Long> input = c.element();
                  if (input.getValue() >= UAMARKPROBABLE) {
                    c.output(KV.of(input.getKey(), true));
                  } else {
                    if (knownGateways.getOrDefault(input.getKey(), false)) {
                      c.output(KV.of(input.getKey(), true));
                    }
                  }
                }
              }));
    }

    /**
     * Returns a {@code UserAgentBased} {@link PTransform} like this one but with a list of known
     * gateways that are parsed from a file. The file should contain an ip per line.
     *
     * @param path Path to load inital gateway list from
     * @return A {@code UserAgentBased} {@link PTransform}
     */
    public UserAgentBased withKnownGateways(String path) {
      return new UserAgentBased(loadGatewayList(path));
    }

    /**
     * Returns a {@code UserAgentBased} {@link PTransform} like this one but with a map of ip
     * addresses that are known already to be gateways.
     *
     * @param knownGateways map containing known gateway ips as keys and True as the value
     * @return A {@code UserAgentBased} {@link PTransform}
     */
    @VisibleForTesting
    public UserAgentBased withKnownGateways(Map<String, Boolean> knownGateways) {
      return new UserAgentBased(knownGateways);
    }
  }

  public static DetectNat.UserAgentBased byUserAgent() {
    return new UserAgentBased(new HashMap<String, Boolean>());
  }

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
      in = DetectNat.class.getResourceAsStream(path);
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
