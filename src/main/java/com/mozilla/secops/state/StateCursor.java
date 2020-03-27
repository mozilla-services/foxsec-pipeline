package com.mozilla.secops.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Generic state cursor implementation */
public abstract class StateCursor<T> {
  private final Logger log;
  protected final Class<T> stateClass;
  protected final ObjectMapper mapper;
  protected ArrayList<StateOperation<T>> operations;
  protected HashMap<UUID, StateOperation<T>> completedOperations;

  /**
   * Add an operation for execution in the cursor
   *
   * @param operation StateOperation
   * @return This for chaining
   * @throws StateException StateException
   */
  public StateCursor<T> withOperation(StateOperation<T> operation) throws StateException {
    // A key is required for everything but GET_ALL
    if (operation.getOperationType() != StateOperation.OperationType.GET_ALL
        && !validKey(operation.getKey())) {
      throw new StateException("invalid key name");
    }
    operations.add(operation);
    return this;
  }

  /**
   * Fetch a result value from a completed operation
   *
   * <p>Only applicable for GET related operations.
   *
   * @param id Operation ID
   * @return T
   * @throws StateException StateException
   */
  public T getResultValueForId(UUID id) throws StateException {
    if (!completedOperations.containsKey(id)) {
      throw new StateException("requested operation id was unknown or not yet completed");
    }
    return completedOperations.get(id).getResultValue();
  }

  /**
   * Fetch a set of result values from a completed operation
   *
   * <p>Only applicable for GET_ALL related operations.
   *
   * @param id Operation ID
   * @return ArrayList
   * @throws StateException StateException
   */
  public ArrayList<T> getResultValuesForId(UUID id) throws StateException {
    if (!completedOperations.containsKey(id)) {
      throw new StateException("requested operation id was unknown or not yet completed");
    }
    return completedOperations.get(id).getResultValues();
  }

  /**
   * Commit transaction
   *
   * <p>If the cursor was created as a transaction, calling this method on the cursor will commit
   * the transaction. If this method is called on a cursor that is not configured as a transaction,
   * an exception will be thrown.
   *
   * @throws StateException StateException
   */
  public abstract void commit() throws StateException;

  /**
   * Execute all operations in cursor
   *
   * @throws StateException
   */
  public void execute() throws StateException {
    completedOperations.clear();
    executeInner();
    operations.clear();
  }

  /**
   * Execute all operations in cursor
   *
   * @throws StateException
   */
  protected void executeInner() throws StateException {
    throw new RuntimeException("executeInner must be overridden by implementing class");
  }

  /**
   * Set a value in state
   *
   * <p>This is a convenience method that will add a single SET operation and call execute.
   *
   * @param key Key
   * @param value Value
   * @throws StateException StateException
   */
  public void set(String key, T value) throws StateException {
    StateOperation<T> o = new StateOperation<T>().set(key, value);
    withOperation(o);
    execute();
  }

  /**
   * Get a value from state
   *
   * <p>This is a convenience method that will add a single GET operation and call execute.
   *
   * @param key Key
   * @return T
   * @throws StateException StateException
   */
  public T get(String key) throws StateException {
    StateOperation<T> o = new StateOperation<T>().get(key);
    withOperation(o);
    execute();
    return getResultValueForId(o.getId());
  }

  /**
   * Get all values from state
   *
   * <p>This is a convenience method that will add a single GET_ALL operation and call execute.
   *
   * @return ArrayList
   * @throws StateException StateException
   */
  public ArrayList<T> getAll() throws StateException {
    StateOperation<T> o = new StateOperation<T>().getAll();
    withOperation(o);
    execute();
    return getResultValuesForId(o.getId());
  }

  private static Boolean validKey(String k) {
    if ((k == null) || (k.isEmpty())) {
      return false;
    }
    return true;
  }

  /**
   * Allocate new {@link StateCursor}
   *
   * @param stateClass Class for state storage
   */
  public StateCursor(Class<T> stateClass) {
    log = LoggerFactory.getLogger(StateCursor.class);
    operations = new ArrayList<StateOperation<T>>();
    completedOperations = new HashMap<UUID, StateOperation<T>>();

    this.stateClass = stateClass;

    mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
  }
}
