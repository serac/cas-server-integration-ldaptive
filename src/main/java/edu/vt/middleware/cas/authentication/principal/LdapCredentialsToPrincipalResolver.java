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

import java.util.HashMap;
import java.util.Map;

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchExecutor;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Simple credentials to principal resolver that searches for attributes of a principal using
 * the user name of a {@link org.jasig.cas.authentication.principal.UsernamePasswordCredentials} instance as the
 * basis of the search query. This component provides an optional simple attribute name mapping facility.
 *
 * @author Middleware Services
 * @version $Revision: $
 */
public class LdapCredentialsToPrincipalResolver implements CredentialsToPrincipalResolver, InitializingBean {

    /** The name of the username parameter in the search filter expression. */
    public static final String USER_PARAM = "user";

    /** User name placeholder in LDAP search filter expression. */
    public static final String USER_PLACEHOLDER = '{' + USER_PARAM + '}';

    /** Logger instance. */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /** Map of directory attribute name to CAS attribute name. */
    private Map<String, String> attributeMapping;

    /** Flag that indicates whether multiple search results are allowed for a given credential. */
    private boolean allowMultipleResults = false;

    /** Attribute that will be used for identifier in resolved principal. */
    @NotNull
    private String userNameAttribute;

    /** Performs the LDAP search operation. */
    @NotNull
    private SearchExecutor searchExecutor;

    /** Source of LDAP connections. */
    @NotNull
    private ConnectionFactory connectionFactory;


    /**
     * Creates a new instance with the requisite parameters.
     *
     * @param  cf  Source of LDAP connections for search operation.
     * @param  se  Executes the search operation.
     * @param  userAttribute  Attribute name in search result used for resolved principal identifier.
     */
    public LdapCredentialsToPrincipalResolver(
            final ConnectionFactory cf, final SearchExecutor se, final String userAttribute) {

        this.connectionFactory = cf;
        this.searchExecutor = se;
        this.userNameAttribute = userAttribute;
    }


    /**
     * Sets whether to allow multiple search results for a given credential.
     * This is false by default, which is sufficient and secure for more deployments.
     * Setting this to true may have security consequences.
     *
     * @param  allowMultiple  True to allow multiple search results in which case the first result
     *                        returned is used to construct the principal, or false to indicate that
     *                        a runtime exception should be raised on multiple search results.
     */
    public void setAllowMultipleResults(final boolean allowMultiple) {
        this.allowMultipleResults = allowMultiple;
    }


    /**
     * Sets the mapping of directory attribute name to CAS attribute name.
     *
     * @param  mapping  Attribute name mapping.  Keys are LDAP directory attribute names and
     *                  values are corresponding CAS attribute names.
     */
    public void setAttributeMapping(final Map<String, String> mapping) {
        this.attributeMapping = mapping;
    }


    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(searchExecutor.getSearchFilter(), "SearchExecutor#searchFilter cannot be null.");
        final String filterString = searchExecutor.getSearchFilter().getFilter();
        Assert.notNull(filterString, "SearchExecutor#searchFilter#filter cannot be null.");
        if (!filterString.contains(USER_PLACEHOLDER)) {
            throw new IllegalArgumentException(
                    "Search filter expression must container user name placeholder " + USER_PLACEHOLDER);
        }
    }


    @Override
    public final boolean supports(final Credentials credentials) {
        return credentials instanceof UsernamePasswordCredentials;
    }


    @Override
    public final Principal resolvePrincipal(final Credentials credentials) {
        final SearchResult result;
        try {
            logger.debug("Attempting to resolve principal from {}.", credentials);
            final Response<SearchResult> response = searchExecutor.search(
                    connectionFactory,
                    filterWithParams(credentials));
            logger.debug("LDAP response: {}", response);
            result = response.getResult();
        } catch (LdapException e) {
            logger.error("LDAP error resolving principal from {}.", credentials, e);
            return null;
        }
        if (result.getEntries().size() > 1 && !allowMultipleResults) {
            throw new IllegalStateException(
                    "Multiple search results found but not allowed (allowMultipleResults=false).");
        }
        final Principal principal;
        if (result.getEntries().isEmpty()) {
            logger.debug("No results found for {}.", credentials);
            principal = null;
        } else {
            principal = principalFromEntry(result.getEntry());
        }
        logger.debug("Resolved principal {}", principal);
        return principal;
    }


    /**
     * Creates a CAS principal from an LDAP entry.
     *
     * @param  entry  LDAP entry.
     *
     * @return  Resolved CAS principal.
     */
    protected Principal principalFromEntry(final LdapEntry entry) {
        final LdapAttribute nameAttribute = entry.getAttribute(userNameAttribute);
        if (nameAttribute == null) {
            logger.warn("Username attribute {} not found on {}; returning null principal.", userNameAttribute, entry);
            return null;
        }
        final String id = nameAttribute.getStringValue();
        final Map<String, Object> attributes = new HashMap<String, Object>(entry.getAttributes().size());
        Object value;
        for (LdapAttribute attribute : entry.getAttributes()) {
            if (userNameAttribute.equals(attribute.getName())) {
                continue;
            }
            if (attribute.size() == 1) {
                value = attribute.getStringValue();
            } else {
                value = attribute.getStringValues();
            }
            attributes.put(mapAttributeName(attribute.getName()), value);
        }
        return new SimplePrincipal(id, attributes);
    }


    /**
     * Maps an LDAP attribute name onto a CAS attribute name.
     *
     * @param  ldapName  LDAP attribute name.
     *
     * @return  Mapped name if a mapping exists for the given attribute, otherwise the original name.
     */
    protected String mapAttributeName(final String ldapName) {
        if (attributeMapping != null) {
            final String localName = attributeMapping.get(ldapName);
            return localName != null ? localName : ldapName;
        }
        return ldapName;
    }


    /**
     * Constructs a new search filter using {@link SearchExecutor#searchFilter} as a template and
     * the username from the credential as a parameter.
     *
     * @param  credentials  Source of username for LDAP search query.
     *
     * @return  Search filter with parameters applied.
     */
    private SearchFilter filterWithParams(final Credentials credentials) {
        if (!(credentials instanceof UsernamePasswordCredentials)) {
            throw new IllegalArgumentException(credentials + " not supported.");
        }
        final SearchFilter filter = new SearchFilter();
        filter.setFilter(searchExecutor.getSearchFilter().getFilter());
        filter.setParameter(USER_PARAM, ((UsernamePasswordCredentials) credentials).getUsername());
        return filter;
    }
}
