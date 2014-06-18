/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
