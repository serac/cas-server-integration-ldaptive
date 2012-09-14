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

import javax.validation.constraints.NotNull;

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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * Provides a simple {@link UserDetailsService} implementation that obtains user details from an LDAP search.
 * Two searches are performed by this component for every user details lookup:
 * <ol>
 *     <li>Search for an entry to resolve the username. In most cases the search should return exactly one result,
 *     but the {@link #setAllowMultipleResults(boolean)} property may be toggled to change that behavior.</li>
 *     <li>Search for groups of which the user is a member. This search commonly occurs on a separate directory
 *     branch than that of the user search.</li>
 * </ol>
 *
 * @author Middleware Services
 * @version $Revision: $
 */
public class LdapUserDetailsService implements UserDetailsService, InitializingBean {

    /** The name of the username parameter in the search filter expression. */
    public static final String USER_PARAM = "user";

    /** User name placeholder in LDAP search filter expression. */
    public static final String USER_PLACEHOLDER = '{' + USER_PARAM + '}';

    /** Default role prefix. */
    public static final String DEFAULT_ROLE_PREFIX = "ROLE_";

    /** Placeholder for unknown password given to user details. */
    public static final String UNKNOWN_PASSWORD = "<UNKNOWN>";

    /** Logger instance. */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /** Source of LDAP connections. */
    @NotNull
    private final ConnectionFactory connectionFactory;

    /** Executes the search query for user data. */
    @NotNull
    private final SearchExecutor userSearchExecutor;

    /** Executes the search query for roles. */
    @NotNull
    private final SearchExecutor roleSearchExecutor;

    /** Name of LDAP attribute to use as principal identifier. */
    @NotNull
    private final String userAttributeName;

    /** Name of LDAP attribute to be used as the basis for role granted authorities. */
    @NotNull
    private final String roleAttributeName;

    /** Prefix appended to the uppercased {@link #roleAttributeName} per the normal Spring Security convention. */
    @NotNull
    private String rolePrefix = DEFAULT_ROLE_PREFIX;

    /** Flag that indicates whether multiple search results are allowed for a given credential. */
    private boolean allowMultipleResults = false;


    /**
     * Creates a new instance with the given required parameters.
     *
     * @param  factory  Source of LDAP connections for searches.
     * @param  userSearchExecutor  Executes the LDAP search for user data.
     * @param roleSearchExecutor  Executes the LDAP search for role data.
     * @param userAttributeName  Name of LDAP attribute that contains username for user details.
     * @param roleAttributeName  Name of LDAP attribute that contains role membership data for the user.
     */
    public LdapUserDetailsService(
            final ConnectionFactory factory,
            final SearchExecutor userSearchExecutor,
            final SearchExecutor roleSearchExecutor,
            final String userAttributeName,
            final String roleAttributeName) {

        this.connectionFactory = factory;
        this.userSearchExecutor = userSearchExecutor;
        this.roleSearchExecutor = roleSearchExecutor;
        this.userAttributeName = userAttributeName;
        this.roleAttributeName = roleAttributeName;
    }


    /**
     * Sets the prefix appended to the uppercase {@link #roleAttributeName} per the normal Spring Security convention.
     * The default value {@value #DEFAULT_ROLE_PREFIX} is sufficient in most cases.
     *
     * @param  rolePrefix  Role prefix.
     */
    public void setRolePrefix(final String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }


    /**
     * Sets whether to allow multiple search results for user details given a username.
     * This is false by default, which is sufficient and secure for more deployments.
     * Setting this to true may have security consequences.
     *
     * @param  allowMultiple  True to allow multiple search results in which case the first result
     *                        returned is used to construct user details, or false to indicate that
     *                        a runtime exception should be raised on multiple search results for user details.
     */
    public void setAllowMultipleResults(final boolean allowMultiple) {
        this.allowMultipleResults = allowMultiple;
    }


    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userSearchExecutor.getSearchFilter(), "UserSearchExecutor#searchFilter cannot be null.");
        final String userSearchFilter = userSearchExecutor.getSearchFilter().getFilter();
        Assert.notNull(userSearchFilter, "UserSearchExecutor#searchFilter#filter cannot be null.");
        if (!userSearchFilter.contains(USER_PLACEHOLDER)) {
            throw new IllegalArgumentException(
                    "Search filter expression must container user name placeholder " + USER_PLACEHOLDER);
        }

        Assert.notNull(userSearchExecutor.getSearchFilter(), "RoleSearchExecutor#searchFilter cannot be null.");
        final String roleSearchFilter = userSearchExecutor.getSearchFilter().getFilter();
        Assert.notNull(roleSearchFilter, "RoleSearchExecutor#searchFilter#filter cannot be null.");
        if (!roleSearchFilter.contains(USER_PLACEHOLDER)) {
            throw new IllegalArgumentException(
                    "Search filter expression must container user name placeholder " + USER_PLACEHOLDER);
        }
    }


    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final SearchResult userResult;
        try {
            logger.debug("Attempting to get details for user {}.", username);
            final Response<SearchResult> response = userSearchExecutor.search(
                    connectionFactory,
                    filterWithParams(userSearchExecutor, username));
            logger.debug("LDAP user search response: {}", response);
            userResult = response.getResult();
        } catch (LdapException e) {
            throw new RuntimeException("LDAP error fetching details for user.", e);
        }
        if (userResult.size() == 0) {
            throw new UsernameNotFoundException(username + " not found.");
        }
        if (userResult.size() > 1 && !allowMultipleResults) {
            throw new IllegalStateException(
                    "Found multiple results for user which is not allowed (allowMultipleResults=false).");
        }
        final String userDn = userResult.getEntry().getDn();
        final LdapAttribute userAttribute = userResult.getEntry().getAttribute(userAttributeName);
        if (userAttribute == null) {
            throw new IllegalStateException(userAttributeName + " attribute not found in results.");
        }
        final String id = userAttribute.getStringValue();

        final SearchResult roleResult;
        try {
            logger.debug("Attempting to get roles for user {}.", userDn);
            final Response<SearchResult> response = roleSearchExecutor.search(
                    connectionFactory,
                    filterWithParams(roleSearchExecutor, userDn));
            logger.debug("LDAP role search response: {}", response);
            roleResult = response.getResult();
        } catch (LdapException e) {
            throw new RuntimeException("LDAP error fetching roles for user.", e);
        }
        LdapAttribute roleAttribute;
        final Collection<SimpleGrantedAuthority> roles = new ArrayList<SimpleGrantedAuthority>(roleResult.size());
        for (LdapEntry entry : roleResult.getEntries()) {
            roleAttribute = entry.getAttribute(roleAttributeName);
            if (roleAttribute == null) {
                logger.warn("Role attribute not found on entry {}", entry);
                continue;
            }
            roles.add(new SimpleGrantedAuthority(rolePrefix + roleAttribute.getStringValue().toUpperCase()));
        }

        return new User(id, UNKNOWN_PASSWORD, roles);
    }



    /**
     * Constructs a new search filter using {@link SearchExecutor#searchFilter} as a template and
     * the username as a parameter.
     *
     * @param  username  Username parameter of search query.
     *
     * @return  Search filter with parameters applied.
     */
    private SearchFilter filterWithParams(final SearchExecutor executor, final String username) {
        final SearchFilter filter = new SearchFilter();
        filter.setFilter(executor.getSearchFilter().getFilter());
        filter.setParameter(USER_PARAM, username);
        return filter;
    }
}
