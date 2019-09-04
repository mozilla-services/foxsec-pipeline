package com.mozilla.secops.input;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
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
 *
 * <p>The class supports two different modes of operation; simplex mode and multiplex mode.
 *
 * <p>In simplex mode, raw events are read from one or more input sources, and the resulting data
 * set is output in a single flat collection as is.
 *
 * <p>In multiplex mode, raw events are read from one or more elements, where each element can have
 * one or more input sources. The resulting data set is output in key value pairs, with the key
 * being the element name and the values being data read from the input streams belonging to that
 * particular element.
 *
 * <p>In both simplex and multiplex mode, the reads can occur in either raw mode or a parsed mode.
 * In raw mode, no attempted parsing of a raw entry will occur, and the resulting data set will
 * simply consist of the raw string data.
 *
 * <p>To enable parsed mode a parser configuration must be supplied. In this mode, the raw data set
 * will be passed through the parser with the resulting data set consistent of {@link Event} objects
 * instead of raw strings.
 *
 * <p>A filter can be associated with parsed read operations to filter events based on what is
 * desired for a particular element.
 */
@JsonInclude(Include.NON_NULL)
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
   * Set operating mode
   *
   * @param mode Operating mode
   */
  @JsonProperty("mode")
  public void setOperatingMode(OperatingMode mode) {
    if (mode.equals(OperatingMode.SIMPLEX)) {
      simplex();
    } else if (mode.equals(OperatingMode.MULTIPLEX)) {
      multiplex();
    } else {
      throw new RuntimeException("invalid operating mode");
    }
  }

  /**
   * Get operating mode
   *
   * @return Operating mode
   */
  public OperatingMode getOperatingMode() {
    return mode;
  }

  /**
   * Set project
   *
   * @param project Project string
   */
  @JsonProperty("gcp_project")
  public void setProject(String project) {
    this.project = project;
  }

  /**
   * Get project
   *
   * @return Project string
   */
  public String getProject() {
    return project;
  }

  /**
   * Set input elements
   *
   * @param elements Input element array
   */
  @JsonProperty("elements")
  public void setInputElements(ArrayList<InputElement> elements) {
    this.elements = elements;
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
    elements.add(
        InputElement.fromPipelineOptions(SIMPLEX_DEFAULT_ELEMENT, options, cfgTickMessage));
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
      return elements.get(0).expandElementRaw(begin, input.getProject());
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
      return elements.get(0).expandElement(begin, input.getProject());
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
                i.expandElementRaw(begin, input.getProject())
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

  /** Return a transform that will ingest data, and emit parsed events in multiplex mode */
  public PTransform<PBegin, PCollection<KV<String, Event>>> multiplexRead() {
    return new MultiplexReader(this);
  }

  /**
   * Read raw events from configured sources, returning a key value collection with the key being
   * the element name and the value being a parsed event
   */
  public static class MultiplexReader extends PTransform<PBegin, PCollection<KV<String, Event>>> {
    private static final long serialVersionUID = 1L;

    private final Input input;

    @Override
    public PCollection<KV<String, Event>> expand(PBegin begin) {
      PCollectionList<KV<String, Event>> list =
          PCollectionList.<KV<String, Event>>empty(begin.getPipeline());
      ArrayList<InputElement> elements = input.getInputElements();
      if (elements.size() < 1) {
        throw new RuntimeException("multiplex read with no elements");
      }
      for (InputElement i : elements) {
        list =
            list.and(
                i.expandElement(begin, input.getProject())
                    .apply(
                        ParDo.of(
                            new DoFn<Event, KV<String, Event>>() {
                              private static final long serialVersionUID = 1L;

                              @ProcessElement
                              public void processElement(ProcessContext c) {
                                c.output(KV.of(i.getName(), c.element()));
                              }
                            })));
      }
      return list.apply(Flatten.<KV<String, Event>>pCollections());
    }

    /**
     * Create new MultiplexReader
     *
     * @param input Prepared Input object
     */
    public MultiplexReader(Input input) {
      this.input = input;
    }
  }
}
