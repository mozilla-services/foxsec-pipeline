package com.mozilla.secops;

import com.google.common.net.InetAddresses;
import java.nio.ByteBuffer;

/**
 * CIDR lookup using radix tree search
 *
 * <p>Only supports IPv4.
 *
 * <p>See also http://www.cs.columbia.edu/~ji/F02/ir04/routing.pdf
 */
public class InetRadix {
  private static class Node {
    public Node left, right;
    public boolean isLeaf;

    Node() {
      left = right = null;
      isLeaf = false;
    }
  }

  private static class Tree {
    Node root;

    // 10000000 00000000 00000000 00000000 (1L << 31)
    private long startBit = 0x80000000L;

    public boolean contains(long ip) {
      long bit = startBit;
      Node n = root;

      while (n != null) {
        if (n.isLeaf) {
          return true;
        }
        if ((ip & bit) != 0) {
          n = n.right;
        } else {
          n = n.left;
        }
        bit = bit >> 1;
      }
      return false;
    }

    public void insert(long ip, long mask) {
      long bit = startBit;

      Node n = root;
      Node next = n;

      while ((bit & mask) != 0) {
        if ((ip & bit) != 0) {
          next = n.right;
        } else {
          next = n.left;
        }
        if (next == null) {
          break;
        }
        bit = bit >> 1;
        n = next;
      }

      if (next != null) {
        n.isLeaf = true;
        return;
      }

      while ((bit & mask) != 0) {
        next = new Node();
        if ((ip & bit) != 0) {
          n.right = next;
        } else {
          n.left = next;
        }
        bit = bit >> 1;
        n = next;
      }

      n.isLeaf = true;
    }

    Tree() {
      root = new Node();
    }
  }

  private Tree tree;

  private long longFromString(String ip) {
    ByteBuffer bb = ByteBuffer.allocate(8);
    bb.putInt(0);
    bb.put(InetAddresses.forString(ip).getAddress());
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

    // Generate a bitmask from our integer mask value, e.g. for a /24:
    //
    // 1 << (32 - 24)
    // 00000000 00000000 00000001 00000000
    // - 1
    // 00000000 00000000 00000000 11111111
    // ^ 0xffffffff
    // 11111111 11111111 11111111 00000000
    long mask = ((1L << (32 - m)) - 1L) ^ 0xffffffffL;

    tree.insert(longFromString(ip), mask);
  }

  /** Create new InetRadix */
  InetRadix() {
    tree = new Tree();
  }
}
