package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestSourceLoginFailure {
  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateSourceLoginFailure(true);
    SourceLoginFailure sut = new SourceLoginFailure(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert on %d login failures from a single source in a %d second window.",
            options.getSourceLoginFailureThreshold(), 300);
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateSourceLoginFailure(false);
    SourceLoginFailure sut = new SourceLoginFailure(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert on %d login failures from a single source in a %d second window. (Experimental)",
            options.getSourceLoginFailureThreshold(), 300);
    assertEquals(expected, doc);
  }
}
