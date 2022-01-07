package com.mozilla.secops.metrics;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.parser.CfgTick;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.beam.sdk.options.PipelineOptions;

/** Builder class for initializating configuration tick messages */
public class CfgTickBuilder {
  private final ObjectMapper mapper;

  private HashMap<String, String> cfgData;

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class PipelineOptionsJson {
    private Map<String, Object> options;

    @JsonProperty("options")
    public Map<String, Object> getOptions() {
      return options;
    }
  }

  private void mergeData(HashMap<String, String> in) {
    in.forEach((k, v) -> cfgData.merge(k, v, (v1, v2) -> new String(v2)));
  }

  /**
   * Add documentation about a transform to the configuration tick
   *
   * @param t {@link com.mozilla.secops.DocumentingTransform}
   */
  public void withTransformDoc(DocumentingTransform t) {
    cfgData.put(String.format("heuristic_%s", t.getClass().getSimpleName()), t.getTransformDoc());
  }

  /** Initialize new {@link CfgTickBuilder} */
  public CfgTickBuilder() {
    mapper = new ObjectMapper();
    mapper.setSerializationInclusion(Include.NON_NULL);
    mapper.setSerializationInclusion(Include.NON_EMPTY);
    cfgData = new HashMap<String, String>();
  }

  private void removeUndesirable() {
    cfgData.remove("filesToStage"); // Just remove the staged jar list if present
  }

  /**
   * Generate configuration tick message from builder contents
   *
   * @return JSON message string
   * @throws IOException IOException
   */
  public String build() throws IOException {
    cfgData.put("configuration_tick", "true");
    removeUndesirable();
    try {
      return mapper.writeValueAsString(cfgData);
    } catch (JsonProcessingException exc) {
      throw new IOException(exc);
    }
  }

  /**
   * Populate builder with pipeline options to include in messages
   *
   * @param opt {@link PipelineOptions}
   * @return CfgTickBuilder
   * @throws IOException IOException
   */
  public CfgTickBuilder includePipelineOptions(PipelineOptions opt) throws IOException {
    String jsonOpt;
    try {
      jsonOpt = mapper.writeValueAsString(opt);
    } catch (JsonProcessingException exc) {
      throw new IOException(exc);
    }
    PipelineOptionsJson p = mapper.readValue(jsonOpt, PipelineOptionsJson.class);
    mergeData(CfgTick.flattenObjectMapToStringMap(p.getOptions()));
    return this;
  }
}
