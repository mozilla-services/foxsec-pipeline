package com.mozilla.secops.state;

import java.util.ArrayList;
import java.util.UUID;

/**
 * Represents a single state operation
 *
 * <p>Represents a single state operation for execution by a cursor.
 */
public class StateOperation<T> {
  private UUID id;
  private String key;
  private T value;
  private T resultValue;
  private ArrayList<T> resultValues;
  private OperationType operationType;

  /** Available state operation types */
  public enum OperationType {
    GET,
    GET_ALL,
    SET
  }

  /**
   * Get operation ID
   *
   * @return UUID
   */
  public UUID getId() {
    return id;
  }

  /**
   * Get key
   *
   * @return String
   */
  public String getKey() {
    return key;
  }

  /**
   * Get value
   *
   * @return T
   */
  public T getValue() {
    return value;
  }

  /**
   * Set result value
   *
   * @param resultValue Result value
   */
  public void setResultValue(T resultValue) {
    this.resultValue = resultValue;
  }

  /**
   * Get result value
   *
   * <p>Return the results of an operation, where the operation should have had a single result
   * (e.g., a key fetch).
   *
   * @return T
   */
  public T getResultValue() {
    return resultValue;
  }

  /**
   * Set result values
   *
   * @param resultValues Result values
   */
  public void setResultValues(ArrayList<T> resultValues) {
    this.resultValues = resultValues;
  }

  /**
   * Get result values
   *
   * <p>Return the results of an operation, where the operation should have had one or more results
   * (e.g., a get all operation).
   *
   * @return ArrayList
   */
  public ArrayList<T> getResultValues() {
    return resultValues;
  }

  /**
   * Get operation type
   *
   * @return OperationType
   */
  public OperationType getOperationType() {
    return operationType;
  }

  /**
   * Configure as a get operation
   *
   * @param key Key for entity to fetch
   * @return This for chaining
   */
  public StateOperation<T> get(String key) {
    operationType = OperationType.GET;
    this.key = key;
    return this;
  }

  /**
   * Configure as a get all operation
   *
   * @return This for chaining
   */
  public StateOperation<T> getAll() {
    operationType = OperationType.GET_ALL;
    return this;
  }

  /**
   * Configure as a set operation
   *
   * @param key Key for entity to set
   * @param value Value to associate with entity state
   * @return This for chaining
   */
  public StateOperation<T> set(String key, T value) {
    operationType = OperationType.SET;
    this.key = key;
    this.value = value;
    return this;
  }

  /** Create new StateOperation */
  public StateOperation() {
    id = UUID.randomUUID();
  }
}
