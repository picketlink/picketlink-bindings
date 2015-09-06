package org.picketlink.test.identity.federation.bindings.wildfly.rest;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.picketlink.identity.federation.bindings.wildfly.rest.SAMLEndpoint;
import org.picketlink.identity.federation.bindings.wildfly.rest.SAMLOAuthEndpoint;
import org.picketlink.identity.federation.bindings.wildfly.rest.SAMLValidationEndpoint;

/**
 * A test JAX-RS {@link javax.ws.rs.core.Application} to test the
 * SAML Endpoint
 *
 * @author Anil Saldhana
 * @since June 09, 2014
 */
@ApplicationPath("/testsaml")
public class TestSAMLApplication extends Application {
    @Override
    public Set<Class<?>> getClasses()
    {
        HashSet<Class<?>> classes = new HashSet<Class<?>>();
        classes.add(SAMLEndpoint.class);
        classes.add(SAMLOAuthEndpoint.class);
        classes.add(SAMLValidationEndpoint.class);
        return classes;
    }
}
