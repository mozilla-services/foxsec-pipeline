package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestCustomsVelocity {
  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateVelocity(true);
    options.setMinimumDistanceForAlert(1000.0);
    CustomsVelocity sut = new CustomsVelocity(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert based on applying location velocity analysis to FxA events, using a maximum KM/s of 0.22 and minimum distance of 1000.00KM",
            options.getPasswordResetAbuseThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocWithMonitorOnly() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateVelocity(true);
    options.setEnableVelocityDetectorMonitorOnly(true);
    options.setMinimumDistanceForAlert(1000.0);
    options.setMinimumDistanceForAlertMonitorOnly(500.0);
    CustomsVelocity sut = new CustomsVelocity(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert based on applying location velocity analysis to FxA events, using a maximum KM/s of 0.22 and minimum distance of 1000.00KM, monitor only using a maximum KM/s of 0.22 and minimum distance of 500.00KM",
            options.getPasswordResetAbuseThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setMinimumDistanceForAlert(1000.0);
    options.setEscalateVelocity(false);
    CustomsVelocity sut = new CustomsVelocity(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert based on applying location velocity analysis to FxA events, using a maximum KM/s of 0.22 and minimum distance of 1000.00KM (Experimental)",
            options.getPasswordResetAbuseThreshold());
    assertEquals(expected, doc);
  }
}
