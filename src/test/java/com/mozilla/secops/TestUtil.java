package com.mozilla.secops;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.zip.GZIPInputStream;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;

/** Various test utility functions */
public class TestUtil {
  /**
   * Read test input as a resource, returning a collection of strings that can be parsed into events
   *
   * @param resource Resource path to load test data from
   * @param p {@link TestPipeline}
   * @return {@link PCollection} of strings
   */
  public static PCollection<String> getTestInput(String resource, TestPipeline p)
      throws IOException {
    ArrayList<String> inputData = new ArrayList<String>();
    InputStream in;
    if (resource.endsWith(".gz")) {
      in = new GZIPInputStream(TestUtil.class.getResourceAsStream(resource));
    } else {
      in = TestUtil.class.getResourceAsStream(resource);
    }
    Scanner scanner = new Scanner(in);
    while (scanner.hasNextLine()) {
      inputData.add(scanner.nextLine());
    }
    scanner.close();
    return p.apply(Create.of(inputData));
  }

  /**
   * Read a resource file returning a string
   *
   * @param resource Resource path to load data from
   * @return String
   */
  public static String getTestResource(String resource) throws IOException {
    InputStream in = TestUtil.class.getResourceAsStream(resource);
    if (in == null) {
      return null;
    }
    try (Scanner scanner = new Scanner(in)) {
      return scanner.useDelimiter("\\A").next();
    }
  }

  /**
   * Read test input as a resource, returning an array of strings, one for each line in the input
   *
   * @param resource Resource path to load test data from
   * @return Array of strings
   */
  public static String[] getTestInputArray(String resource) throws IOException {
    ArrayList<String> inputData = new ArrayList<String>();

    BufferedReader in =
        new BufferedReader(new InputStreamReader(TestUtil.class.getResourceAsStream(resource)));
    String s;
    while ((s = in.readLine()) != null) {
      inputData.add(s);
    }
    return inputData.toArray(new String[0]);
  }
}
