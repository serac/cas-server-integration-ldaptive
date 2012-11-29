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

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.ldaptive.Credential;
import org.ldaptive.LdapException;
import org.ldaptive.auth.AccountState;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LDAP authentication handler that uses the ldaptive <code>Authenticator</code> component underneath.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
public class LdapAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    /** Logger instance. */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /** Performs LDAP authentication given username/password. */
    @NotNull
    private final Authenticator authenticator;


    /**
     * Creates a new authentication handler that delegates to the given authenticator.
     *
     * @param  authenticator  Ldaptive authenticator component.
     */
    public LdapAuthenticationHandler(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }


    @Override
    protected boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials credentials)
            throws AuthenticationException {

        final AuthenticationResponse response;
        try {
            logger.debug("Attempting LDAP authentication for {}", credentials);
            response = authenticator.authenticate(
                    new AuthenticationRequest(credentials.getUsername(), new Credential(credentials.getPassword())));
        } catch (LdapException e) {
            throw new RuntimeException("Unexpected LDAP error", e);
        }
        logger.debug("LDAP response: {}", response);
        if (response.getResult()) {
            return true;
        }
        final AccountState state = response.getAccountState();
        if (state != null && state.getError() != null) {
            try {
                state.getError().throwSecurityException();
            } catch (GeneralSecurityException e) {
                throw new WrappedGeneralSecurityException(e);
            }
        }
        throw BadCredentialsAuthenticationException.ERROR;
    }
}
