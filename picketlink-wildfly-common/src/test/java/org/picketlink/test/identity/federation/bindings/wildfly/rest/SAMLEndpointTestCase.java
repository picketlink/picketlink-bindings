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

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.xml.bind.DatatypeConverter;

import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.picketlink.identity.federation.api.saml.api.SAMLClient;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.test.identity.federation.bindings.wildfly.TestClassIntrospector;
import org.picketlink.test.identity.federation.bindings.wildfly.TestIdentityManager;

import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import io.undertow.servlet.api.WebResourceCollection;

/**
 * Unit Test the {@link org.picketlink.identity.federation.bindings.wildfly.rest.SAMLEndpoint}
 * @author Anil Saldhana
 * @since June 09, 2014
 */
public class SAMLEndpointTestCase {
    private static final String server_url = "http://localhost:8080";

    private static UndertowJaxrsServer server;

    @BeforeClass
    public static void init() throws Exception {
        System.setProperty("org.jboss.resteasy.port", "8080");

        server = new UndertowJaxrsServer().start();
        deployApplication();
    }

    @AfterClass
    public static void stop() throws Exception {
        server.stop();
    }

    protected static void deployApplication() throws Exception {
        TestIdentityManager identityManager = new TestIdentityManager();
        identityManager.addUser("user1", "password1", "role1");

        LoginConfig loginConfig = new LoginConfig("FORM", "Test Realm", "/FormLoginServlet","/error.html");

        LoginConfig basicLoginConfig = new LoginConfig("BASIC", "TESTREALM");
        DeploymentInfo di = server.undertowDeployment(TestSAMLApplication.class);
        di.setContextPath("/test").setDeploymentName("testsaml");

        di.setClassIntrospecter(TestClassIntrospector.INSTANCE)
                .setIdentityManager(identityManager)
                .setLoginConfig(basicLoginConfig);

        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.addWebResourceCollection(new WebResourceCollection()
                .addUrlPattern("/test/*"))
                .addRoleAllowed("role1")
                .setEmptyRoleSemantic(SecurityInfo.EmptyRoleSemantic.DENY);


        ServletInfo restEasyServlet = di.getServlets().values().iterator().next();
        restEasyServlet.setServletSecurityInfo(new ServletSecurityInfo().addRoleAllowed("role1"));

        di.addSecurityConstraint(securityConstraint);

        server.deploy(di);
    }

    @Test
    public void testSAML() throws Exception{
        Client client = ClientBuilder.newClient().register(new Authenticator("user1", "password1"));
        WebTarget webTarget = client.target(server_url).path("/test/testsaml/saml");
        Form form = new Form();
        form.param("x", "foo");
        form.param("y", "bar");

        Entity entity = Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        Response response = webTarget.request().post(entity);
        assertNotNull(response);
        int status = response.getStatus();
        assertEquals("Expected 200", 200, status);
        String samlAssertionBase64Encoded = response.readEntity(String.class);
        assertNotNull(samlAssertionBase64Encoded);
        byte[] assertionBytes = PostBindingUtil.base64Decode(samlAssertionBase64Encoded);

        SAMLClient samlClient = new SAMLClient();
        AssertionType assertionType = samlClient.parseAssertion(assertionBytes);
        assertNotNull(assertionType);

        assertFalse(samlClient.hasExpired(assertionType));
        NameIDType nameIDType = (NameIDType) assertionType.getSubject().getSubType().getBaseID();
        assertEquals("user1", nameIDType.getValue());
    }

    public class Authenticator implements ClientRequestFilter {

        private final String user;
        private final String password;

        public Authenticator(String user, String password) {
            this.user = user;
            this.password = password;
        }

        public void filter(ClientRequestContext requestContext) throws IOException {
            MultivaluedMap<String, Object> headers = requestContext.getHeaders();
            final String basicAuthentication = getBasicAuthentication();
            headers.add("Authorization", basicAuthentication);
        }

        private String getBasicAuthentication() {
            String token = this.user + ":" + this.password;
            try {
                return "Basic " + DatatypeConverter.printBase64Binary(token.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                throw new IllegalStateException("Cannot encode with UTF-8", ex);
            }
        }
    }
}
