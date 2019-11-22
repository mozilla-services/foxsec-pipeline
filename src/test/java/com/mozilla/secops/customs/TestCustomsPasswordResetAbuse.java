package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestCustomsPasswordResetAbuse {
  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalatePasswordResetAbuse(true);
    CustomsPasswordResetAbuse sut = new CustomsPasswordResetAbuse(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert of single source requests password reset for at least %d distinct accounts "
                + "within %d minute fixed window.",
            options.getPasswordResetAbuseWindowThresholdPerIp(), 10);
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalatePasswordResetAbuse(false);
    CustomsPasswordResetAbuse sut = new CustomsPasswordResetAbuse(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert of single source requests password reset for at least %d distinct accounts "
                + "within %d minute fixed window. (Experimental)",
            options.getPasswordResetAbuseWindowThresholdPerIp(), 10);
    assertEquals(expected, doc);
  }
}
