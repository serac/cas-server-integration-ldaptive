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
package edu.vt.middleware.cas.authentication.handler;

import java.security.GeneralSecurityException;

import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * Adapts a {@link java.security.GeneralSecurityException} onto a CAS {@link AuthenticationException}
 * via the wrapper pattern.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
public class WrappedGeneralSecurityException extends AuthenticationException {

    /** Error code for a wrapped exception. */
    public static final String CODE = "error.authentication.wrapped";

    /** Wrapped exception. */
    private final GeneralSecurityException cause;


    /**
     * Creates a new instance that wraps the given exception.
     *
     * @param  e  Exception to wrap.
     */
    public WrappedGeneralSecurityException(final GeneralSecurityException e) {
        super(CODE);
        this.cause = e;
    }


    /**
     * Gets the {@link GeneralSecurityException} that this instance wraps.
     *
     * @return  Wrapped exception.
     */
    @Override
    public Exception getCause() {
        return cause;
    }
}
