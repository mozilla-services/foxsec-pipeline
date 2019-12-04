package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestCustomsAccountCreation {

  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateAccountCreation(true);
    CustomsAccountCreation sut = new CustomsAccountCreation(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address creates %d or more accounts within 10 minute fixed window.",
            options.getAccountCreationThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateAccountCreation(false);
    CustomsAccountCreation sut = new CustomsAccountCreation(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address creates %d or more accounts within 10 minute fixed "
                + "window. (Experimental)",
            options.getAccountCreationThreshold());
    assertEquals(expected, doc);
  }
}
