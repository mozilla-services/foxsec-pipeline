package com.mozilla.secops;

/** A transform that will return a documentation string */
public interface DocumentingTransform {
  /**
   * Get documentation string from transform based on it's current configuration
   *
   * @return String
   */
  public String getTransformDoc();
}
