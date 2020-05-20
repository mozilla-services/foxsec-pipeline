package com.mozilla.secops;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * CIDR lookup using radix tree search
 *
 * <p>Only supports IPv4.
 */
public class InetRadix {
  private static class Node {
    public Node l, r, p;
    public Boolean v;

    Node() {
      l = r = p = null;
      v = null;
    }
  }

  private static class Tree {
    Node root;

    private long startBit = 0x80000000L;

    public boolean contains(long ip) {
      long bit = startBit;
      Node n = root;
      boolean ret = false;

      while (n != null) {
        if (n.v != null) {
          ret = n.v;
        }
        if ((ip & bit) != 0) {
          n = n.r;
        } else {
          n = n.l;
        }
        if ((0xffffffffL & bit) == 0) {
          break;
        }
        bit = bit >> 1;
      }
      return ret;
    }

    public void insert(long ip, long mask) {
      long bit = startBit;

      Node n = root;
      Node next = n;

      while ((bit & mask) != 0) {
        if ((ip & bit) != 0) {
          next = n.r;
        } else {
          next = n.l;
        }
        if (next == null) {
          break;
        }
        bit = bit >> 1;
        n = next;
      }

      if (next != null) {
        n.v = true;
        return;
      }

      while ((bit & mask) != 0) {
        next = new Node();
        next.p = n;
        if ((ip & bit) != 0) {
          n.r = next;
        } else {
          n.l = next;
        }
        bit = bit >> 1;
        n = next;
      }

      n.v = true;
    }

    Tree() {
      root = new Node();
    }
  }

  private Tree tree;

  private long longFromString(String ip) {
    ByteBuffer bb = ByteBuffer.allocate(8);
    bb.putInt(0);
    try {
      bb.put(InetAddress.getByName(ip).getAddress());
    } catch (UnknownHostException exc) {
      throw new IllegalArgumentException(exc.getMessage());
    }
    bb.rewind();
    return bb.getLong();
  }

  /**
   * Determine if tree contains a subnet that would contain IP
   *
   * @param ip IP address
   * @return True if tree contained subnet that contains IP
   */
  public boolean contains(String ip) {
    return tree.contains(longFromString(ip));
  }

  /**
   * Add IPv4 CIDR subnet to tree
   *
   * @param cidr CIDR subnet specification
   */
  public void add(String cidr) {
    int i = cidr.indexOf("/");
    String ip = cidr.substring(0, i);
    int m = Integer.parseInt(cidr.substring(i + 1));

    long mask = ((1L << (32 - m)) - 1L) ^ 0xffffffffL;

    tree.insert(longFromString(ip), mask);
  }

  /** Create new InetRadix */
  InetRadix() {
    tree = new Tree();
  }
}
