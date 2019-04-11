package com.mozilla.secops;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.mozilla.secops.crypto.RuntimeSecrets;
import java.io.IOException;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/**
 * {@link SqsIO} provides an IO transform for writing messages to SQS
 *
 * <p>Although an SQS output transform exists in the standard Beam SDK this differs slightly in that
 * it supports per-invocation AWS credentials, and does not rely on global pipeline option based AWS
 * credential specification.
 */
public class SqsIO {
  /**
   * Parse an input queue specification, returning each element
   *
   * <p>The expected format is queueurl:accesskey:secret:region
   *
   * @param input Input string
   * @return Output array containing each element, or null if invalid
   */
  public static String[] parseQueueInfo(String input) {
    String[] parts = input.split(":");
    if (parts.length != 5) {
      return null;
    }
    return new String[] {parts[0] + ":" + parts[1], parts[2], parts[3], parts[4]};
  }

  /**
   * Return {@link PTransform} to write messages to SQS
   *
   * @param sqsQueueInfo SQS queue information, url:key:secret:region
   * @param project GCP project name, only required if decrypting queue infomration via cloudkms
   * @return IO transform
   */
  public static Write write(String sqsQueueInfo, String project) {
    try {
      sqsQueueInfo = RuntimeSecrets.interpretSecret(sqsQueueInfo, project);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
    String[] parts = parseQueueInfo(sqsQueueInfo);
    if (parts == null) {
      throw new RuntimeException("format of sqs queue information was invalid");
    }
    return new Write(parts[0], parts[1], parts[2], parts[3]);
  }

  public static class Write extends PTransform<PCollection<String>, PDone> {
    private static final long serialVersionUID = 1L;

    private final String queueUrl;
    private final String key;
    private final String secret;
    private final String region;

    /**
     * Create new SqsIO write transfrom
     *
     * @param queueUrl SQS queue URL
     * @param key AWS access key
     * @param secret AWS secret
     * @param region Region identifier
     */
    public Write(String queueUrl, String key, String secret, String region) {
      this.queueUrl = queueUrl;
      this.key = key;
      this.secret = secret;
      this.region = region;
    }

    @Override
    public PDone expand(PCollection<String> input) {
      input
          .apply(
              "convert to sqs message",
              ParDo.of(
                  new DoFn<String, SendMessageRequest>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      c.output(
                          new SendMessageRequest()
                              .withDelaySeconds(0)
                              .withMessageBody(c.element())
                              .withQueueUrl(queueUrl));
                    }
                  }))
          .apply("write to sqs", ParDo.of(new SqsWriteFn(queueUrl, key, secret, region)));
      return PDone.in(input.getPipeline());
    }
  }

  private static class SqsWriteFn extends DoFn<SendMessageRequest, Void> {
    private static final long serialVersionUID = 1L;

    private transient AmazonSQS sqs;
    private final String queueUrl;
    private final String key;
    private final String secret;
    private final String region;

    SqsWriteFn(String queueUrl, String key, String secret, String region) {
      this.queueUrl = queueUrl;
      this.key = key;
      this.secret = secret;
      this.region = region;
    }

    @Setup
    public void setup() {
      sqs =
          AmazonSQSClientBuilder.standard()
              .withRegion(Regions.fromName(region))
              .withCredentials(
                  new AWSStaticCredentialsProvider(new BasicAWSCredentials(key, secret)))
              .build();
    }

    @ProcessElement
    public void processElement(ProcessContext processContext) throws Exception {
      sqs.sendMessage(processContext.element());
    }

    @Teardown
    public void teardown() throws Exception {
      if (sqs != null) {
        sqs.shutdown();
      }
    }
  }
}
