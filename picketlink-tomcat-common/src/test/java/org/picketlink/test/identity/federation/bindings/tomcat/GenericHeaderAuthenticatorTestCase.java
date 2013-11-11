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
package org.picketlink.test.identity.federation.bindings.tomcat;

import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.session.StandardManager;
import org.apache.catalina.session.StandardSession;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.picketlink.identity.federation.bindings.tomcat.AbstractGenericHeaderAuthenticator;

import javax.servlet.http.Cookie;

import java.net.HttpCookie;
import java.security.Principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.*;

/**
 * Unit test {@link org.picketlink.identity.federation.bindings.tomcat.AbstractGenericHeaderAuthenticator}
 * @author Anil Saldhana
 * @since November 11, 2013
 */
public class GenericHeaderAuthenticatorTestCase {

    private String userName = "anil";
    private String passWord = "123";

    private Principal thePrincipal = null;

    public class GenericHeaderAuthenticatorInTest extends AbstractGenericHeaderAuthenticator{
    }

    @Test
    public void testGenericHeaderAuthenticator() throws Exception{
        GenericHeaderAuthenticatorInTest auth = new GenericHeaderAuthenticatorInTest();
        Request mockRequest = mock(Request.class);
        Response mockResponse = mock(Response.class);
        LoginConfig mockLoginConfig = mock(LoginConfig.class);
        Context mockContext = mock(Context.class);

        auth.setContainer(mockContext);
        auth.setHttpHeaderForSSOAuth("USER");
        auth.setSessionCookieForSSOAuth("MYCOOKIE");

        TestRealm testRealm = new TestRealm();
        when(mockContext.getRealm()).thenReturn(testRealm);

        //When SSLValve asks the request for the header, provide it a certificate string
        when(mockRequest.getHeader("USER")).thenReturn(userName);

        //When there is getCookies call on the request, provide a Cookie[]
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return new Cookie[] { new Cookie("MYCOOKIE", passWord)};
            }
        }).when(mockRequest).getCookies();

        //When there is a call to Catalina Session, create one
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                return new StandardSession(new StandardManager());
            }
        }).when(mockRequest).getSessionInternal(Mockito.anyBoolean());

        //When there is a call to Request.setUserPrincipal, we have a callback where we set to our local principal
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                thePrincipal = (Principal) args[0];
                return null;
            }
        }).when(mockRequest).setUserPrincipal(Mockito.any(Principal.class));

        boolean result = auth.performAuthentication(mockRequest,mockResponse,mockLoginConfig);
        assertTrue(result);

        assertNotNull(thePrincipal);
        assertEquals(userName,thePrincipal.getName());
    }

    //Construct a test realm
    public class TestRealm extends RealmBase {

        @Override
        protected String getName() {
            return null;
        }

        @Override
        protected String getPassword(String s) {
            return null;
        }

        @Override
        protected Principal getPrincipal(String s) {
            return null;
        }

        @Override
        public Principal authenticate(String username, String credentials) {
            if(userName.equalsIgnoreCase(username) && passWord.equals(credentials)){

                return new Principal() {
                    @Override
                    public String getName() {
                        return userName;
                    }
                };
            }
            return null;
        }
    }
}