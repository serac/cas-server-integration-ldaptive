/*
  $Id: $

  Copyright (C) 2012 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: $
  Updated: $Date: $
*/
package edu.vt.middleware.cas.monitor;

import org.jasig.cas.monitor.AbstractNamedMonitor;
import org.jasig.cas.monitor.Status;
import org.jasig.cas.monitor.StatusCode;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapException;
import org.ldaptive.pool.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Monitors an ldaptive {@link ConnectionFactory}.  While this class can be used with instances of
 * {@link org.ldaptive.pool.PooledConnectionFactory}, the {@link PooledConnectionFactoryMonitor} class is preferable.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
public class ConnectionFactoryMonitor extends AbstractNamedMonitor<Status> {

    /** OK status. */
    private static final Status OK = new Status(StatusCode.OK);

    /** Error status. */
    private static final Status ERROR = new Status(StatusCode.ERROR);

    /** Logger instance. */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /** Source of connections to validate. */
    private final ConnectionFactory connectionFactory;

    /** Connection validator. */
    private final Validator<Connection> validator;


    /**
     * Creates a new instance that monitors the given connection factory.
     *
     * @param  factory  Connection factory to monitor.
     * @param  validator  Validates connections from the factory.
     */
    public ConnectionFactoryMonitor(final ConnectionFactory factory, final Validator<Connection> validator) {
        this.connectionFactory = factory;
        this.validator = validator;
    }


    /**
     * Gets a connection from the underlying connection factory and attempts to validate it.
     *
     * @return  Status with code {@link StatusCode#OK} on success otherwise {@link StatusCode#ERROR}.
     */
    public Status observe() {
        Connection conn = null;
        try {
            conn = connectionFactory.getConnection();
            if (!conn.isOpen()) {
                conn.open();
            }
            return validator.validate(conn) ? OK : ERROR;
        } catch (LdapException e) {
            logger.warn("Validation failed with error.", e);
        } finally {
            if (conn != null && conn.isOpen()) {
                conn.close();
            }
        }
        return ERROR;
    }
}
