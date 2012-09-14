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
package edu.vt.middleware.cas.userdetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;

/**
 * Unit test for the {@link LdapUserDetailsService} class.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"/applicationContext-test.xml"})
public class LdapUserDetailsServiceTest {

    @Autowired
    private LdapUserDetailsService userDetailsService;

    @Autowired
    @Qualifier("testUserDetails")
    private Properties testUserDetails;


    @Test
    public void testLoadUserByUsername() throws Exception {
        String[] roles;
        User expected;
        for (String user : testUserDetails.stringPropertyNames()) {
            expected = parseUserDetails(testUserDetails.get(user).toString());
            assertEquals(expected, userDetailsService.loadUserByUsername(user));
        }
    }

    private User parseUserDetails(final String s) {
        final String[] userRoles = s.split(":");
        final String[] roles = userRoles[1].split("\\|");
        final Collection<SimpleGrantedAuthority> roleAuthorities = new ArrayList<SimpleGrantedAuthority>(roles.length);
        for (String role : roles) {
            roleAuthorities.add(new SimpleGrantedAuthority(role));
        }
        return new User(userRoles[0], LdapUserDetailsService.UNKNOWN_PASSWORD, roleAuthorities);
    }
}
