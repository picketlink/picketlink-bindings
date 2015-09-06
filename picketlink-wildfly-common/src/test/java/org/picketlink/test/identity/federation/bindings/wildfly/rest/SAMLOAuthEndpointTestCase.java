package org.picketlink.test.identity.federation.bindings.wildfly.rest;

import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import io.undertow.servlet.api.WebResourceCollection;
import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.identity.federation.api.saml.api.SAMLClient;
import org.picketlink.identity.federation.bindings.wildfly.rest.SAMLOauthInfo;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.test.identity.federation.bindings.wildfly.TestClassIntrospector;
import org.picketlink.test.identity.federation.bindings.wildfly.TestIdentityManager;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * Unit test the {@link org.picketlink.identity.federation.bindings.wildfly.rest.SAMLOAuthEndpoint}
 * @author Anil Saldhana
 * @since June 16, 2014
 */
public class SAMLOAuthEndpointTestCase extends UndertowJaxrsBaseTest{

    private final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer";

    private final String GRANT_TYPE_PARAMETER = "grant_type";

    private final String ASSERTION_PARAMETER = "assertion";

    @Test
    public void testSAMLOAuth() throws Exception {
        Client client = restClient("user1", "password1");
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

        String assertionID = assertionType.getID();

        assertFalse(samlClient.hasExpired(assertionType));
        NameIDType nameIDType = (NameIDType) assertionType.getSubject().getSubType().getBaseID();
        assertEquals("user1", nameIDType.getValue());

        //Now let us use the SAML assertion to call the oauth endpoint
        form = new Form();
        form.param(GRANT_TYPE_PARAMETER,GRANT_TYPE);
        form.param(ASSERTION_PARAMETER,samlAssertionBase64Encoded);
        entity = Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        webTarget = client.target(server_url).path("/test/testsaml/samloauth");
        response = webTarget.request().post(entity);
        assertNotNull(response);
        status = response.getStatus();
        assertEquals("Expected 200", 200, status);

        SAMLOauthInfo samlOauthInfo = response.readEntity(SAMLOauthInfo.class);
        assertNotNull(samlOauthInfo);
        assertEquals(assertionID, samlOauthInfo.getSamlAssertionID());

        //Let us call the endpoint to validate the assertion
        form = new Form();
        form.param(ASSERTION_PARAMETER,samlAssertionBase64Encoded);
        entity = Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        webTarget = client.target(server_url).path("/test/testsaml/samlvalidate");
        assertFalse(samlClient.hasExpired(assertionType));

        response = webTarget.request().post(entity);
        assertNotNull(response);
        status = response.getStatus();
        assertEquals("Expected 200", 200, status);

        assertEquals("true", response.readEntity(String.class));
    }
}
