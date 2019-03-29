package com.mozilla.secops;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Scanner;

/** Various utilities for file IO */
public class FileUtil {
  /**
   * Read file from specified path, returning an {@link ArrayList} containing an item for each line
   *
   * @param path Resource path or GCS URL to read file from
   * @return {@link ArrayList} containing line items
   */
  public static ArrayList<String> fileReadLines(String path) throws IOException {
    InputStream in;
    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = CidrUtil.class.getResourceAsStream(path);
    }
    if (in == null) {
      throw new IOException("failed to read file from specified path");
    }
    ArrayList<String> ret = new ArrayList<>();
    Scanner s = new Scanner(in);
    while (s.hasNext()) {
      ret.add(s.next());
    }
    return ret;
  }
}
