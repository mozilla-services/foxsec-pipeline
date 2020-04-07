package com.mozilla.secops.state;

import java.io.IOException;
import java.net.InetSocketAddress;
import net.spy.memcached.MemcachedClient;

/** Utilize a memcached instance for centralized state storage */
public class MemcachedStateInterface implements StateInterface {
  private final String memcachedHost;
  private final int memcachedPort;
  private MemcachedClient memclient;

  /** {@inheritDoc} */
  public <T> StateCursor<T> newCursor(Class<T> stateClass, boolean transaction)
      throws StateException {
    if (transaction) {
      throw new StateException("memcached state interface does not support transactions");
    }
    return new MemcachedStateCursor<T>(memclient, stateClass);
  }

  /** {@inheritDoc} */
  public void done() {
    memclient.shutdown();
  }

  /** {@inheritDoc} */
  public void deleteAll() throws StateException {
    memclient.flush();
  }

  /** {@inheritDoc} */
  public void initialize() throws StateException {
    try {
      memclient = new MemcachedClient(new InetSocketAddress(memcachedHost, memcachedPort));
    } catch (IOException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  /**
   * Initialize a memcached state interface
   *
   * @param host Hostname of memcached instance
   * @param port Port of memcached instance
   */
  public MemcachedStateInterface(String host, int port) {
    memcachedHost = host;
    memcachedPort = port;
  }
}
