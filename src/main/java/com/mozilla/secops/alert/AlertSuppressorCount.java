package com.mozilla.secops.alert;

/**
 * Extended alert suppression using count metadata
 *
 * <p>Extends {@link AlertSuppressor} to also take into account the count metadata value in an
 * alert. The same expiry logic is applied, however in this case if a new alert comes in for a key
 * we have state for and the metadata count value is different then what was seen prior, the alert
 * will be emitted and state will be updated.
 *
 * <p>If this transform is applied to values that do not contain a count metadata field a {@link
 * RuntimeException} will be thrown.
 */
public class AlertSuppressorCount extends AlertSuppressor {
  private static final long serialVersionUID = 1L;

  /**
   * Initialize new AlertSuppressorCount
   *
   * @param expiry State expiry timer in seconds
   */
  public AlertSuppressorCount(Long expiry) {
    super(expiry);
  }

  @Override
  protected Boolean shouldSuppress(AlertSuppressionState ss, AlertSuppressionState newss) {
    if ((ss.count == null) || (newss.count == null)) {
      throw new RuntimeException("count based suppression with null count value");
    }
    if (!(ss.count.equals(newss.count))) {
      log.info("new count value for {}, will emit", ss.key);
      return false;
    }
    return true;
  }
}
