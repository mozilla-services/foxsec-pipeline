package com.mozilla.secops.state;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import net.spy.memcached.MemcachedClient;
import net.spy.memcached.OperationTimeoutException;

/**
 * Memcached state cursor implementation
 *
 * <p>This implementation does not support transactions.
 */
public class MemcachedStateCursor<T> extends StateCursor<T> {
  private MemcachedClient memclient;

  public void commit() throws StateException {
    throw new StateException("memcached state cursor does not support transactions");
  }

  @Override
  public void executeInner() throws StateException {
    // The memcached implementation is simple and will just execute the operations in the
    // order they have been specified.
    for (StateOperation<T> o : operations) {
      switch (o.getOperationType()) {
        case GET:
          String readbuf = null;
          try {
            readbuf = (String) memclient.get(o.getKey());
          } catch (OperationTimeoutException exc) {
            throw new StateException(exc.getMessage());
          }
          if (readbuf == null) {
            break;
          }
          try {
            o.setResultValue(mapper.readValue(readbuf, stateClass));
          } catch (IOException exc) {
            throw new StateException(exc.getMessage());
          }
          break;
        case GET_ALL:
          throw new RuntimeException("GET_ALL not implemented for MemcachedStateCursor");
        case SET:
          try {
            String writebuf = mapper.writeValueAsString(o.getValue());
            memclient.set(o.getKey(), 0, writebuf);
          } catch (JsonProcessingException exc) {
            throw new StateException(exc.getMessage());
          }
          break;
        default:
          throw new RuntimeException("unknown operation type");
      }
      completedOperations.put(o.getId(), o);
    }
  }

  /**
   * Initialize a new Memcached state cursor
   *
   * @param memclient {@link MemcachedClient}
   * @param stateClass Class for state storage
   */
  public MemcachedStateCursor(MemcachedClient memclient, Class<T> stateClass) {
    super(stateClass);
    this.memclient = memclient;
  }
}
