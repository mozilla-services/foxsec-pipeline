package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.ArrayList;

/** Options that can be passed along with the event to a {@link GroovyEventFilter} */
public class GroovyEventFilterOptions implements Serializable {
  private static final long serialVersionUID = 1L;

  private String stackdriverProject;
  private ArrayList<String> stackdriverLabels;
  private ArrayList<String> excludeRequestPath;
  private ArrayList<String> includeUrlHostRegex;

  /**
   * Set Stackdriver project filter
   *
   * @param stackdriverProject String
   */
  public void setStackdriverProject(String stackdriverProject) {
    this.stackdriverProject = stackdriverProject;
  }

  /**
   * Get Stackdriver project filter
   *
   * @return String
   */
  public String getStackdriverProject() {
    return stackdriverProject;
  }

  /**
   * Add a Stackdriver label
   *
   * @param label String
   */
  public void addStackdriverLabel(String label) {
    stackdriverLabels.add(label);
  }

  /**
   * Get Stackdriver label filters
   *
   * @return ArrayList
   */
  public ArrayList<String> getStackdriverLabels() {
    return stackdriverLabels;
  }

  /**
   * Add request path exclusion
   *
   * @param path String
   */
  public void addExcludeRequestPath(String path) {
    excludeRequestPath.add(path);
  }

  /**
   * Get request path exclusion list
   *
   * @return ArrayList
   */
  public ArrayList<String> getExcludeRequestPath() {
    return excludeRequestPath;
  }

  /**
   * Add URL host inclusion regex
   *
   * @param regex String
   */
  public void addIncludeUrlHostRegex(String regex) {
    includeUrlHostRegex.add(regex);
  }

  /**
   * Get URL host inclusion regex list
   *
   * @return ArrayList
   */
  public ArrayList<String> getIncludeUrlHostRegex() {
    return includeUrlHostRegex;
  }

  /** Create new EventFilterOptions */
  public GroovyEventFilterOptions() {
    stackdriverLabels = new ArrayList<String>();
    excludeRequestPath = new ArrayList<String>();
    includeUrlHostRegex = new ArrayList<String>();
  }
}
