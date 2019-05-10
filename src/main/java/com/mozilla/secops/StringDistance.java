package com.mozilla.secops;

import java.util.Arrays;

/** Levenshtein string distance calculation */
public class StringDistance {
  private static int sCost(char a, char b) {
    return a == b ? 0 : 1;
  }

  private static int min(int... n) {
    return Arrays.stream(n).min().orElse(Integer.MAX_VALUE);
  }

  /**
   * Calculate similarity ratio between two strings
   *
   * @param x First string
   * @param y Second string
   * @return Calculated ratio
   */
  public static Double ratio(String x, String y) {
    if ((x == null) || (y == null)) {
      throw new RuntimeException("ratio called with null string values");
    }
    int maxlen = x.length();
    if (y.length() > maxlen) {
      maxlen = y.length();
    }
    return calculate(x, y) / (double) maxlen;
  }

  /**
   * Return string distance value between two strings
   *
   * @param x First string
   * @param y Second string
   * @return Calculated distance
   */
  public static int calculate(String x, String y) {
    if ((x == null) || (y == null)) {
      throw new RuntimeException("calculate called with null string values");
    }
    int[][] dp = new int[x.length() + 1][y.length() + 1];

    for (int i = 0; i <= x.length(); i++) {
      for (int j = 0; j <= y.length(); j++) {
        if (i == 0) {
          dp[i][j] = j;
        } else if (j == 0) {
          dp[i][j] = i;
        } else {
          dp[i][j] =
              min(
                  dp[i - 1][j - 1] + sCost(x.charAt(i - 1), y.charAt(j - 1)),
                  dp[i - 1][j] + 1,
                  dp[i][j - 1] + 1);
        }
      }
    }

    return dp[x.length()][y.length()];
  }
}
