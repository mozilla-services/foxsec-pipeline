package com.mozilla.secops;

import groovy.lang.GroovyShell;
import groovy.lang.MissingMethodException;
import groovy.lang.Script;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

/** Execute Groovy scripts from within pipeline functions */
public class ScriptRunner {
  private final GroovyShell shell;
  private HashMap<String, Script> loadedScripts;

  /**
   * Load a script into the script runner
   *
   * @param path Script path, resource path or GCS URL
   * @param name Name to register script with
   * @throws IOException IOException
   */
  public void loadScript(String path, String name) throws IOException {
    InputStream in = FileUtil.getStreamFromPath(path);
    loadedScripts.put(name, shell.parse(new InputStreamReader(in)));
  }

  /**
   * Invoke method within loaded script
   *
   * @param name Script name
   * @param method Method to execute
   * @param clazz Class for return type
   * @param args Arguments to method
   * @param <T> T
   * @return T
   */
  public <T> T invokeMethod(String name, String method, Class<T> clazz, Object... args) {
    try {
      return clazz.cast(loadedScripts.get(name).invokeMethod(method, args));
    } catch (MissingMethodException exc) {
      throw new IllegalArgumentException(exc.getMessage());
    }
  }

  /** Initialize new {@link ScriptRunner} */
  public ScriptRunner() {
    shell = new GroovyShell();
    loadedScripts = new HashMap<String, Script>();
  }
}
