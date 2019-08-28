package com.mozilla.secops.input;

import com.mozilla.secops.InputOptions;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;

/**
 * Standard data ingestion
 *
 * <p>The {@link Input} class can be used to configured and execute various forms of pipeline raw
 * event ingestion from external sources.
 */
public class Input {
  private enum OperatingMode {
    SIMPLEX,
    MULTIPLEX,
    UNSPECIFIED
  }

  private static final String SIMPLEX_DEFAULT_ELEMENT = "default";

  private OperatingMode mode = OperatingMode.UNSPECIFIED;
  private ArrayList<InputElement> elements;
  private String project;

  /**
   * Adapter to simplify {@link Input} usage for pipelines that used previous composite input
   * tranform
   *
   * @param options InputOptions
   * @param cfgTick Configuration tick message, null if not enabled
   */
  public static PTransform<PBegin, PCollection<String>> compositeInputAdapter(
      InputOptions options, String cfgTick) throws IOException {
    return new Input(options.getProject())
        .simplex()
        .fromPipelineOptions(options, cfgTick)
        .simplexReadRaw();
  }

  /**
   * Get input elements
   *
   * @return Input elements
   */
  public ArrayList<InputElement> getInputElements() {
    return elements;
  }

  /**
   * Enable simplex input mode
   *
   * @return this for chaining
   */
  public Input simplex() {
    mode = OperatingMode.SIMPLEX;
    return this;
  }

  /**
   * Configure input using specified {@link InputOptions}
   *
   * <p>This method is only valid in simplex operating mode.
   *
   * @param options Pipeline input options
   * @param cfgTickMessage Configuration tick message, null if not enabled
   * @return this for chaining
   */
  public Input fromPipelineOptions(InputOptions options, String cfgTickMessage) throws IOException {
    if (!mode.equals(OperatingMode.SIMPLEX)) {
      throw new IOException("method only valid in simplex mode");
    }

    InputElement element = new InputElement(SIMPLEX_DEFAULT_ELEMENT);

    if (options.getGenerateConfigurationTicksInterval() > 0) {
      element.setConfigurationTicks(
          cfgTickMessage,
          options.getGenerateConfigurationTicksInterval(),
          options.getGenerateConfigurationTicksMaximum());
    }

    if (options.getInputFile() != null) {
      for (String buf : options.getInputFile()) {
        element.addFileInput(buf);
      }
    }

    if (options.getInputPubsub() != null) {
      for (String buf : options.getInputPubsub()) {
        element.addPubsubInput(buf);
      }
    }

    if (options.getInputKinesis() != null) {
      for (String buf : options.getInputKinesis()) {
        element.addKinesisInput(KinesisInput.fromInputSpecifier(buf, project));
      }
    }

    elements.add(element);
    return this;
  }

  /**
   * Enable multiplex mode
   *
   * @return this for chaining
   */
  public Input multiplex() {
    mode = OperatingMode.MULTIPLEX;
    return this;
  }

  /** Create new input object */
  public Input() {
    elements = new ArrayList<InputElement>();
  }

  /**
   * Create new input object
   *
   * <p>This variant should be used if any input options require KMS decryption, typically the case
   * for pipelines executing in Dataflow.
   *
   * @param project GCP project
   */
  public Input(String project) {
    this();
    this.project = project;
  }

  public PTransform<PBegin, PCollection<String>> simplexReadRaw() {
    return new SimplexReaderRaw(this);
  }

  /**
   * Read raw events from configured sources, combining all events into a single output collection
   * as strings
   */
  public static class SimplexReaderRaw extends PTransform<PBegin, PCollection<String>> {
    private static final long serialVersionUID = 1L;

    private final Input input;

    @Override
    public PCollection<String> expand(PBegin begin) {
      ArrayList<InputElement> elements = input.getInputElements();
      if (elements.size() != 1) {
        throw new RuntimeException("simplex read must have exactly one input element");
      }
      return elements.get(0).expandElementRaw(begin);
    }

    /**
     * Create new SimplexReaderRaw
     *
     * @param input Prepared Input object
     */
    public SimplexReaderRaw(Input input) {
      this.input = input;
    }
  }
}
