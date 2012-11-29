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

import org.jasig.cas.monitor.AbstractPoolMonitor;
import org.jasig.cas.monitor.StatusCode;
import org.ldaptive.Connection;
import org.ldaptive.pool.PooledConnectionFactory;
import org.ldaptive.pool.Validator;

/**
 * Monitors an ldaptive {@link PooledConnectionFactory}.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
public class PooledConnectionFactoryMonitor extends AbstractPoolMonitor {

    /** Source of connections to validate. */
    private final PooledConnectionFactory connectionFactory;

    /** Connection validator. */
    private final Validator<Connection> validator;


    /**
     * Creates a new instance that monitors the given pooled connection factory.
     *
     * @param  factory  Connection factory to monitor.
     * @param  validator  Validates connections from the factory.
     */
    public PooledConnectionFactoryMonitor(
            final PooledConnectionFactory factory, final Validator<Connection> validator) {
        this.connectionFactory = factory;
        this.validator = validator;
    }


    @Override
    protected StatusCode checkPool() throws Exception {
        final Connection conn = connectionFactory.getConnection();
        try {
            return validator.validate(conn) ? StatusCode.OK : StatusCode.ERROR;
        } finally {
            conn.close();
        }
    }

    @Override
    protected int getIdleCount() {
        return connectionFactory.getConnectionPool().availableCount();
    }

    @Override
    protected int getActiveCount() {
        return connectionFactory.getConnectionPool().activeCount();
    }
}
