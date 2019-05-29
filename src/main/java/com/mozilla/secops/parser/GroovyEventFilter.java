package com.mozilla.secops.parser;

import com.mozilla.secops.ScriptRunner;
import java.io.IOException;
import org.apache.beam.sdk.transforms.DoFn;

/** Filter events using a Groovy script */
public class GroovyEventFilter extends DoFn<Event, Event> {
  private static final long serialVersionUID = 1L;

  private transient ScriptRunner runner;

  private String path;
  private String method;
  private GroovyEventFilterOptions efOpt;

  /**
   * Prepare the object for matching events
   *
   * <p>This loads the required script and initializes {@link ScriptRunner}.
   *
   * <p>This should not be called directly if using the object in a ParDo as the function will be
   * called as part of Setup.
   *
   * <p>If calling the match function manually the prepare method should be called first.
   */
  public void prepare() {
    runner = new ScriptRunner();
    try {
      runner.loadScript(path, path);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
  }

  /**
   * Determine if event matches filter
   *
   * @param e Event
   * @return True on match
   */
  public Boolean matches(Event e) {
    return runner.invokeMethod(path, method, Boolean.class, new Object[] {e, efOpt});
  }

  /**
   * Initialize new GroovyEventFilter
   *
   * @param path Script path
   * @param method Method to execute
   * @param efOpt {@link GroovyEventFilterOptions} to pass to match method
   */
  public GroovyEventFilter(String path, String method, GroovyEventFilterOptions efOpt) {
    this.path = path;
    this.method = method;
    this.efOpt = efOpt;
  }

  @Setup
  public void setup() {
    prepare();
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Event e = c.element();
    if (matches(e)) {
      c.output(e);
    }
  }
}
