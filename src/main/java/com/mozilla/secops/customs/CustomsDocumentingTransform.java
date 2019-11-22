package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;

interface CustomsDocumentingTransform extends DocumentingTransform {

  public static final String EXPERIMENTAL_TAG = " (Experimental)";

  /**
   * Get documentation description from transform based on it's current configuration
   *
   * @return String
   */
  String getTransformDocDescription();

  /**
   * Get whether the transform is experimental and won't be escalated
   *
   * @return String
   */
  boolean isExperimental();

  default String getTransformDoc() {
    String experimental = isExperimental() ? EXPERIMENTAL_TAG : "";
    return String.format("%s%s", getTransformDocDescription(), experimental);
  }
}
