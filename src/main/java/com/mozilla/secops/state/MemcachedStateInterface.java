package com.mozilla.secops.state;

import net.spy.memcached.MemcachedClient;
import net.spy.memcached.OperationTimeoutException;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;

/**
 * Utilize a memcached instance for centralized state storage
 */
public class MemcachedStateInterface implements StateInterface {
    private final String memcachedHost;
    private final int memcachedPort;
    private MemcachedClient memclient;

    public String getObject(String s) throws StateException {
        try {
            return (String)memclient.get(s);
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

    public void done() {
        memclient.shutdown();
    }

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
