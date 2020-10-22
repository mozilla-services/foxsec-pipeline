package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestCustomsAccountEnumeration {
  @Test
  public void TestTransformDocWithVarianceWithEscalation() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEnableAccountEnumerationDetector(true);
    options.setEnableContentServerVarianceDetection(true);
    options.setEscalateAccountEnumerationDetector(true);
    CustomsAccountEnumeration sut = new CustomsAccountEnumeration(options, null);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address checks %d or more distinct emails are FxA accounts within 10 minute"
                + " fixed window, using content server variance.",
            options.getAccountEnumerationThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocWithoutVarianceWithEscalation() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEnableAccountEnumerationDetector(true);
    options.setEnableContentServerVarianceDetection(false);
    options.setEscalateAccountEnumerationDetector(true);
    CustomsAccountEnumeration sut = new CustomsAccountEnumeration(options, null);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address checks %d or more distinct emails are FxA accounts within 10 minute"
                + " fixed window, without using content server variance.",
            options.getAccountEnumerationThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocWithVarianceWithoutEscalation() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEnableAccountEnumerationDetector(true);
    options.setEnableContentServerVarianceDetection(true);
    options.setEscalateAccountEnumerationDetector(false);
    CustomsAccountEnumeration sut = new CustomsAccountEnumeration(options, null);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address checks %d or more distinct emails are FxA accounts within 10 minute"
                + " fixed window, using content server variance. (Experimental)",
            options.getAccountEnumerationThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocWithoutVarianceWithoutEscalation() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEnableAccountEnumerationDetector(true);
    options.setEnableContentServerVarianceDetection(false);
    options.setEscalateAccountEnumerationDetector(false);
    CustomsAccountEnumeration sut = new CustomsAccountEnumeration(options, null);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address checks %d or more distinct emails are FxA accounts within 10 minute"
                + " fixed window, without using content server variance. (Experimental)",
            options.getAccountEnumerationThreshold());
    assertEquals(expected, doc);
  }
}
