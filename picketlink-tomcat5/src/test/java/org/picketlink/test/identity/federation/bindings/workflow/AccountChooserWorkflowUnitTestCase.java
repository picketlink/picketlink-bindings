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
package org.picketlink.test.identity.federation.bindings.workflow;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.valves.ValveBase;
import org.junit.Test;
import org.picketlink.identity.federation.bindings.tomcat.sp.AbstractAccountChooserValve;
import org.picketlink.identity.federation.bindings.tomcat.sp.AccountChooserValve;
import org.picketlink.identity.federation.bindings.tomcat.sp.SPPostFormAuthenticator;
import org.picketlink.identity.federation.web.core.IdentityServer;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContext;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContextClassLoader;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRealm;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRequest;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaResponse;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaSession;

/**
 * PLINK-344: Account Chooser at the SP
 * @author Anil Saldhana
 * @since January 21, 2014
 */
public class AccountChooserWorkflowUnitTestCase{
    private String profile = "saml2/post";
    private ClassLoader tcl = Thread.currentThread().getContextClassLoader();
    private String domainName = "MyDomain";

    @Test
    public void testAccountChoosingforDomainA() throws Exception{
        AccountChooserValve accountChooserValve = new AccountChooserValve();
        accountChooserValve.setDomainName(domainName);
        accountChooserValve.setAccountIDPMapProvider(MyAccountMapProvider.class.getName());

        MockCatalinaSession mockCatalinaSession = new MockCatalinaSession();

        MockCatalinaContext servletContext = new MockCatalinaContext();
        // First we go to the employee application
        MockCatalinaContextClassLoader mclSPEmp = setupTCL(profile + "/sp/employee");
        Thread.currentThread().setContextClassLoader(mclSPEmp);
        SPPostFormAuthenticator spEmpl = new SPPostFormAuthenticator();

        MockCatalinaContext context = new MockCatalinaContext();
        context.setPath("/employee");
        spEmpl.setContainer(context);
        spEmpl.testStart();

        LoginConfig loginConfig = new LoginConfig();
        context.setLoginConfig(loginConfig);

        MockCatalinaRealm realm = new MockCatalinaRealm("anil", "test", new Principal() {
            public String getName() {
                return "anil";
            }
        });

        context.setRealm(realm);
        spEmpl.setNext(new NoopValve());

        accountChooserValve.setContainer(context);
        accountChooserValve.setNext(spEmpl);

        MockCatalinaRequest catalinaRequest = new MockCatalinaRequest();
        catalinaRequest.setSession(mockCatalinaSession);

        MockCatalinaResponse catalinaResponse = new MockCatalinaResponse();
        catalinaRequest.setResponse(catalinaResponse);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        catalinaResponse.setOutputStream(baos);

        accountChooserValve.invoke(catalinaRequest,catalinaResponse);

        //Ensure that the account chooser page was set as the forward path
        assertTrue(catalinaRequest.getForwardPath().contains("account"));

        //Assume user chose DomainA
        catalinaRequest.setParameter(AbstractAccountChooserValve.ACCOUNT_PARAMETER, "DomainA");
        accountChooserValve.invoke(catalinaRequest,catalinaResponse);

        //Ensure that the NoopValve was called and we need authentication of the user to mimic AuthenticatorBase.invoke
        assertEquals(catalinaRequest.getAttribute("NEED_AUTH"), "true");

        //Now let us go ahead and authenticate the user
        spEmpl.authenticate(catalinaRequest, catalinaResponse, loginConfig);

        String spResponse = new String(baos.toByteArray());

        //Ensure that the SP is trying to redirect to idp1 which is the equivalent for DomainA
        assertTrue(spResponse.contains("http://idp1"));

        //Also ensure that we do have a local cookie set by the SP
        assertEquals("DomainA", cookieValue(catalinaResponse));
    }

    @Test
    public void testAccountChoosingforDomainB() throws Exception{
        AccountChooserValve accountChooserValve = new AccountChooserValve();
        accountChooserValve.setDomainName(domainName);
        accountChooserValve.setAccountIDPMapProvider(MyAccountMapProvider.class.getName());

        MockCatalinaSession mockCatalinaSession = new MockCatalinaSession();

        MockCatalinaContext servletContext = new MockCatalinaContext();
        // First we go to the employee application
        MockCatalinaContextClassLoader mclSPEmp = setupTCL(profile + "/sp/employee");
        Thread.currentThread().setContextClassLoader(mclSPEmp);
        SPPostFormAuthenticator spEmpl = new SPPostFormAuthenticator();

        MockCatalinaContext context = new MockCatalinaContext();
        context.setPath("/employee");
        spEmpl.setContainer(context);
        spEmpl.testStart();

        LoginConfig loginConfig = new LoginConfig();
        context.setLoginConfig(loginConfig);

        MockCatalinaRealm realm = new MockCatalinaRealm("anil", "test", new Principal() {
            public String getName() {
                return "anil";
            }
        });

        context.setRealm(realm);

        spEmpl.setNext(new NoopValve());

        accountChooserValve.setContainer(context);
        accountChooserValve.setNext(spEmpl);

        MockCatalinaRequest catalinaRequest = new MockCatalinaRequest();
        catalinaRequest.setSession(mockCatalinaSession);

        MockCatalinaResponse catalinaResponse = new MockCatalinaResponse();
        catalinaRequest.setResponse(catalinaResponse);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        catalinaResponse.setOutputStream(baos);

        accountChooserValve.invoke(catalinaRequest,catalinaResponse);

        //Ensure that the account chooser page was set as the forward path
        assertTrue(catalinaRequest.getForwardPath().contains("account"));

        //Assume user chose DomainB
        catalinaRequest.setParameter(AbstractAccountChooserValve.ACCOUNT_PARAMETER, "DomainB");
        accountChooserValve.invoke(catalinaRequest,catalinaResponse);

        //Ensure that the NoopValve was called and we need authentication of the user to mimic AuthenticatorBase.invoke
        assertEquals(catalinaRequest.getAttribute("NEED_AUTH"), "true");

        //Now let us go ahead and authenticate the user
        spEmpl.authenticate(catalinaRequest, catalinaResponse, loginConfig);

        String spResponse = new String(baos.toByteArray());

        //Ensure that the SP is trying to redirect to idp2 which is the equivalent for DomainB
        assertTrue(spResponse.contains("http://idp2"));

        //Also ensure that we do have a local cookie set by the SP
        assertEquals("DomainB",cookieValue(catalinaResponse));
    }


    private MockCatalinaContextClassLoader setupTCL(String resource) {
        URL[] urls = new URL[] { tcl.getResource(resource) };

        MockCatalinaContextClassLoader mcl = new MockCatalinaContextClassLoader(urls);
        mcl.setDelegate(tcl);
        mcl.setProfile(resource);
        return mcl;
    }

    // Get the Identity server
    private IdentityServer getIdentityServer(HttpSession session) {
        IdentityServer server = new IdentityServer();
        server.sessionCreated(new HttpSessionEvent(session));
        return server;
    }

    protected String cookieValue(Response response){
        Cookie[] cookies = response.getCookies();
        if(cookies != null){
            for (Cookie cookie : cookies) {
                if (cookie.getDomain().equalsIgnoreCase(domainName)) {
                    // Found a cookie with the same domain name
                    String cookieName = cookie.getName();
                    if (AbstractAccountChooserValve.ACCOUNT_CHOOSER_COOKIE_NAME.equals(cookieName)) {
                        // Found cookie
                        return cookie.getValue();
                    }
                }
            }
        }
        return null;
    }

    private class NoopValve extends ValveBase{
        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            MockCatalinaRequest mockCatalinaRequest = (MockCatalinaRequest) request;
            mockCatalinaRequest.setAttribute("NEED_AUTH", "true");
        }
    }

    public static class MyAccountMapProvider implements AbstractAccountChooserValve.AccountIDPMapProvider{
        @Override
        public void setServletContext(ServletContext servletContext) {
        }

        @Override
        public void setClassLoader(ClassLoader classLoader) {
        }

        @Override
        public Map<String, String> getIDPMap() throws IOException {
            Map<String,String> map = new HashMap<String, String>();
            map.put("DomainA","http://idp1");
            map.put("DomainB","http://idp2");
            return map;
        }
    }
}