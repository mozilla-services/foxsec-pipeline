package com.mozilla.secops.input;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.parser.Event;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * Standard data ingestion
 *
 * <p>The {@link Input} class can be used to configured and execute various forms of pipeline raw
 * event ingestion from external sources.
 */
public class Input implements Serializable {
  private static final long serialVersionUID = 1L;

  private enum OperatingMode {
    SIMPLEX,
    MULTIPLEX,
    UNSPECIFIED
  }

  /** Default simplex element name */
  public static final String SIMPLEX_DEFAULT_ELEMENT = "default";

  private OperatingMode mode = OperatingMode.UNSPECIFIED;
  private transient ArrayList<InputElement> elements;
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

  /**
   * Add input element
   *
   * @param el Input element
   * @return this for chaining
   */
  public Input withInputElement(InputElement el) throws IOException {
    if ((mode.equals(OperatingMode.SIMPLEX)) && (elements.size() == 1)) {
      throw new IOException("attempt to add more than one element to simplex input");
    }
    elements.add(el);
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

  /** Return a transform that will ingest data, and emit raw strings in simplex mode */
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

  /** Return a transform that will ingest data, and emit parsed events in simplex mode */
  public PTransform<PBegin, PCollection<Event>> simplexRead() {
    return new SimplexReader(this);
  }

  /**
   * Read raw events from configured sources, combining all events into a single output collection
   * as Event objects
   */
  public static class SimplexReader extends PTransform<PBegin, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private final Input input;

    @Override
    public PCollection<Event> expand(PBegin begin) {
      ArrayList<InputElement> elements = input.getInputElements();
      if (elements.size() != 1) {
        throw new RuntimeException("simplex read must have exactly one input element");
      }
      return elements.get(0).expandElement(begin);
    }

    /**
     * Create new SimplexReader
     *
     * @param input Prepared Input object
     */
    public SimplexReader(Input input) {
      this.input = input;
    }
  }

  /** Return a transform that will ingest data, and emit raw events in multiplex mode */
  public PTransform<PBegin, PCollection<KV<String, String>>> multiplexReadRaw() {
    return new MultiplexReaderRaw(this);
  }

  /**
   * Read raw events from configured sources, returning a key value collection with the key being
   * the element name and the value being a raw string
   */
  public static class MultiplexReaderRaw
      extends PTransform<PBegin, PCollection<KV<String, String>>> {
    private static final long serialVersionUID = 1L;

    private final Input input;

    @Override
    public PCollection<KV<String, String>> expand(PBegin begin) {
      PCollectionList<KV<String, String>> list =
          PCollectionList.<KV<String, String>>empty(begin.getPipeline());
      ArrayList<InputElement> elements = input.getInputElements();
      if (elements.size() < 1) {
        throw new RuntimeException("multiplex read with no elements");
      }
      for (InputElement i : elements) {
        list =
            list.and(
                i.expandElementRaw(begin)
                    .apply(
                        ParDo.of(
                            new DoFn<String, KV<String, String>>() {
                              private static final long serialVersionUID = 1L;

                              @ProcessElement
                              public void processElement(ProcessContext c) {
                                c.output(KV.of(i.getName(), c.element()));
                              }
                            })));
      }
      return list.apply(Flatten.<KV<String, String>>pCollections());
    }

    /**
     * Create new MultiplexReaderRaw
     *
     * @param input Prepared Input object
     */
    public MultiplexReaderRaw(Input input) {
      this.input = input;
    }
  }
}
