package com.mozilla.secops.state;

import net.spy.memcached.MemcachedClient;
import net.spy.memcached.OperationTimeoutException;

/**
 * Memcached state cursor implementation
 *
 * <p>This implementation does not support transactions.
 */
public class MemcachedStateCursor extends StateCursor {
  private MemcachedClient memclient;

  public void commit() throws StateException {}

  public String getObject(String s) throws StateException {
    try {
      return (String) memclient.get(s);
    } catch (OperationTimeoutException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  public void saveObject(String s, String v) throws StateException {
    try {
      memclient.set(s, 0, v);
    } catch (IllegalArgumentException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  /**
   * Initialize a new Memcached state cursor
   *
   * @param memclient {@link MemcachedClient}
   */
  public MemcachedStateCursor(MemcachedClient memclient) {
    this.memclient = memclient;
  }
}
