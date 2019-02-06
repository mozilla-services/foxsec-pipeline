package com.mozilla.secops.crypto;

import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.CryptoKeyPathName;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import com.mozilla.secops.GcsUtil;
import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Class for decryption of secrets during pipeline runtime
 *
 * <p>This class makes use of cloud KMS for encryption/decryption operations.
 *
 * <p>It will also make use of GCS if a GCS URL is provided when calling interpretSecret.
 */
public class RuntimeSecrets {
  private KeyManagementServiceClient kmsclient;
  private CryptoKeyPathName keypath;
  private CryptoKeyName keyname;

  private final String project;
  private final String location;
  private final String ring;
  private final String keyName;

  /**
   * Create new {@link RuntimeSecrets} object referencing a KMS key based on the supplied
   * parameters.
   *
   * @param project Project name
   * @param ring Keyring name
   * @param keyName Key name
   */
  public RuntimeSecrets(String project, String ring, String keyName) throws IOException {
    kmsclient = KeyManagementServiceClient.create();

    this.project = project;
    this.location = "global"; // Expect global location for now
    this.ring = ring;
    this.keyName = keyName;

    keypath = CryptoKeyPathName.of(project, location, ring, keyName);
    keyname = CryptoKeyName.of(project, location, ring, keyName);
  }

  /**
   * Encrypt the supplied input
   *
   * @param input Input string
   * @return Base64 encoded encrypted data
   */
  public String encrypt(String input) {
    EncryptResponse resp = kmsclient.encrypt(keypath, ByteString.copyFromUtf8(input));
    return new String(Base64.getEncoder().encode(resp.getCiphertext().toByteArray()));
  }

  /**
   * Decrypt the supplied input
   *
   * @param input Input string
   * @return Decrypted output string
   */
  public String decrypt(String input) {
    DecryptResponse resp =
        kmsclient.decrypt(
            keyname, ByteString.copyFrom(Base64.getDecoder().decode(input.getBytes())));
    return new String(resp.getPlaintext().toByteArray());
  }

  /**
   * Indicate {@link RuntimeSecrets} object will no longer be used, must be called to shutdown
   * background threads
   */
  public void done() throws InterruptedException {
    kmsclient.close();
    kmsclient.awaitTermination(5, TimeUnit.SECONDS);
  }

  /**
   * Interpret a runtime secret as specified in pipeline options.
   *
   * <p>This function currently handles three formats. A string prefixed with cloudkms:// is
   * interpreted as an encrypted string which will be decrypted via CloudKMS. The project should be
   * set to the correct GCP project name. The key ring and key name will always be looked for as
   * "dataflow".
   *
   * <p>With no prefix, the input is simply returned as is and treated as an unencrypted string.
   *
   * <p>If a GCS URL is provided (e.g., gs://bucket/path) - the content of the object at the
   * specified path will be fetched and handled as if it was passed directly as a string into the
   * function.
   *
   * @param input Input string
   * @param project GCP project name, can be null if unapplicable
   * @return Transformed runtime secret
   */
  public static String interpretSecret(String input, String project) throws IOException {
    if (GcsUtil.isGcsUrl(input)) {
      input = GcsUtil.fetchStringContent(input);
    }
    String ret = input;
    if (input.startsWith("cloudkms://")) {
      RuntimeSecrets r = new RuntimeSecrets(project, "dataflow", "dataflow");
      ret = r.decrypt(input.replace("cloudkms://", ""));
      try {
        r.done();
      } catch (InterruptedException exc) {
        throw new IOException(exc.getMessage());
      }
    }
    return ret;
  }

  /** main routine can be used to encrypt or decrypt data on the command line */
  public static void main(String[] args) throws Exception {
    Options options = new Options();

    Option project = new Option("p", "project", true, "GCP project name");
    project.setRequired(true);
    options.addOption(project);

    Option ring = new Option("r", "ring", true, "KMS key ring name");
    ring.setRequired(true);
    options.addOption(ring);

    Option key = new Option("k", "key", true, "KMS key name");
    key.setRequired(true);
    options.addOption(key);

    Option input = new Option("i", "input", true, "Value for encryption/decryption");
    input.setRequired(true);
    options.addOption(input);

    Option decrypt = new Option("d", "decrypt", false, "Decrypt rather than encrypt");
    options.addOption(decrypt);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter fmt = new HelpFormatter();
    CommandLine cmd = null;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      fmt.printHelp("RuntimeSecrets", options);
      System.exit(1);
    }

    RuntimeSecrets r =
        new RuntimeSecrets(
            cmd.getOptionValue("project"), cmd.getOptionValue("ring"), cmd.getOptionValue("key"));
    if (cmd.hasOption("decrypt")) {
      System.out.println(r.decrypt(cmd.getOptionValue("input")));
    } else {
      System.out.println(r.encrypt(cmd.getOptionValue("input")));
    }
    r.done();
  }
}
