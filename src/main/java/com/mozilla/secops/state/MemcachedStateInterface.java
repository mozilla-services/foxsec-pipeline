package com.mozilla.secops.state;

import net.spy.memcached.MemcachedClient;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;

public class MemcachedStateInterface implements StateInterface {
    private String memcachedHost;
    private MemcachedClient memclient;

    public String getObject(String s) {
        return (String)memclient.get(s);
    }

    public void saveObject(String s, String v) {
        memclient.set(s, 0, v);
    }

    public void done() {
        memclient.shutdown();
    }

    public void initialize() throws IOException {
        memclient = new MemcachedClient(new InetSocketAddress(memcachedHost, 11211));
    }

    public MemcachedStateInterface(String host) throws IOException {
        memcachedHost = host;
    }
}
