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
package edu.vt.middleware.cas.authentication.principal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Unit test for {@link LdapCredentialsToPrincipalResolver} class.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"/applicationContext-test.xml"})
public class LdapCredentialsToPrincipalResolverTest {
    /** Pattern used to parse expected attributes from properties file. */
    private static final Pattern ATTR_PATTERN = Pattern.compile("(\\w+):([^;]+)");

    @Autowired
    private LdapCredentialsToPrincipalResolver resolver;

    @Autowired
    @Qualifier("testPrincipals")
    private Properties testPrincipals;


    @Test
    public void testResolvePrincipal() throws Exception {
        String[] values;
        String expectedPrincipalId;
        Map<String, Object> expectedAttributes;
        SimplePrincipal principal;
        for (String username : testPrincipals.stringPropertyNames()) {
            values = testPrincipals.get(username).toString().split(":", 2);
            expectedPrincipalId = values[0];
            expectedAttributes = parseAttributes(values[1]);
            principal = (SimplePrincipal) resolver.resolvePrincipal(newCredentials(username));
            assertNotNull(principal);
            assertEquals(expectedPrincipalId, principal.getId());
            assertEquals(expectedAttributes, principal.getAttributes());
        }
    }


    private Map<String, Object> parseAttributes(final String value) {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        if (!value.startsWith("{") || !value.endsWith("}")) {
            throw new IllegalArgumentException("Invalid attribute listing " + value);
        }
        final Matcher matcher = ATTR_PATTERN.matcher(value.substring(1, value.length() - 1));
        String attribute;
        String attributeValue;
        while (matcher.find()) {
            attribute = matcher.group(1);
            attributeValue = matcher.group(2);
            if (attributeValue.contains("|")) {
                attributes.put(attribute, Arrays.asList(attributeValue.split("\\|")));
            } else {
                attributes.put(attribute, attributeValue);
            }
        }
        return attributes;
    }


    private UsernamePasswordCredentials newCredentials(final String user) {
        final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials();
        credentials.setUsername(user);
        return credentials;
    }
}
