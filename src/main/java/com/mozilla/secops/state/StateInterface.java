package com.mozilla.secops.state;

import java.io.IOException;

/**
 * Interface for state implementations
 */
public interface StateInterface {
    /**
     * Retrieve object from state
     *
     * @param s State key
     * @return Stored state JSON
     */
    public String getObject(String s) throws StateException;
    /**
     * Save object to state
     *
     * @param s State key
     * @param v State JSON
     */
    public void saveObject(String s, String v) throws StateException;
    /**
     * Notify state implementation no further processing will occur
     */
    public void done();
    /**
     * Perform and setup required to read and write state
     */
    public void initialize() throws StateException;
}
