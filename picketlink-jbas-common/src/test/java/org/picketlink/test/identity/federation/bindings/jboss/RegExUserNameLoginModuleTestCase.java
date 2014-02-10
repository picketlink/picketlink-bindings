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
package org.picketlink.test.identity.federation.bindings.jboss;

import org.jboss.security.SimplePrincipal;
import org.junit.Test;
import org.picketlink.identity.federation.bindings.jboss.auth.RegExUserNameLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNull;

/**
 * Unit test the {@link org.picketlink.identity.federation.bindings.jboss.auth.RegExUserNameLoginModule}
 * @author Anil Saldhana
 * @since February 10, 2014
 */
public class RegExUserNameLoginModuleTestCase {
    private String key = "javax.security.auth.login.name";

    /**
     * This test is for the use case when the shared state has a principal that is of {@link java.lang.String} type
     * @throws Exception
     */
    @Test
    public void testUsingString() throws Exception{
        Principal principal =process("UID=007, EMAILADDRESS=something@something, CN=James Bond, O=SpyAgency");
        assertEquals("007", principal.getName());
    }

    /**
     * This test is for the use case when the shared state has a principal that is of {@link java.security.Principal} type
     * @throws Exception
     */
    @Test
    public void testUsingPrincipal() throws Exception{
        Principal principal = new SimplePrincipal("UID=007, EMAILADDRESS=something@something, CN=James Bond, O=SpyAgency");
        assertEquals("007", process(principal).getName());
    }

    /**
     * This test is for the use case where the regular expression on the login module does not match
     * the principal passed in the shared state. In that case, the principal is just returned
     * @throws Exception
     */
    @Test
    public void testMissedExpression() throws Exception{
        String value = "SomePrincipal";
        Principal principal = process("SomePrincipal");
        assertEquals(value, principal.getName()); //Regular Expression Matching Failed
    }

    private Principal process(Object principal) throws Exception{

        RegExUserNameLoginModule regExUserNameLoginModule = new RegExUserNameLoginModule();
        Subject subject = new Subject();
        CallbackHandler cbh = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

            }
        };

        Map<String,Object> sharedState = new HashMap<String,Object>();
        Map<String,Object> options = new HashMap<String,Object>();

        sharedState.put(key,principal);

        options.put("regex","UID=(.*?)\\,");

        regExUserNameLoginModule.initialize(subject, cbh, sharedState, options);

        assertTrue(regExUserNameLoginModule.login());

        Principal thePrincipal = (Principal) sharedState.get(key);
        return thePrincipal;
    }
}