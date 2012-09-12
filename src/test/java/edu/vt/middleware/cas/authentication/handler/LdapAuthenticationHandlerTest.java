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

import java.util.Properties;

import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Unit test for {@link LdapAuthenticationHandler}.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"/applicationContext-test.xml"})
public class LdapAuthenticationHandlerTest {
    @Autowired
    private LdapAuthenticationHandler handler;

    @Autowired
    @Qualifier("testCredentials")
    private Properties testCredentials;


    @Test
    public void testAuthenticate() throws Exception {
        String [] values;
        String password;
        String expected;
        for (String username : testCredentials.stringPropertyNames()) {
            values = testCredentials.get(username).toString().split("\\|");
            password = values[0];
            expected = values[1];
            if (Boolean.TRUE.toString().equalsIgnoreCase(expected)) {
                assertEquals(true, handler.authenticate(newCredentials(username, password)));
            } else {
                try {
                    handler.authenticate(newCredentials(username, password));
                    fail("Should have thrown " + expected);
                } catch (Exception e) {
                    assertEquals(expected, e.getClass().getSimpleName());
                }
            }
        }
    }

    private UsernamePasswordCredentials newCredentials(final String user, final String pass) {
        final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials();
        credentials.setUsername(user);
        credentials.setPassword(pass);
        return credentials;
    }
}
