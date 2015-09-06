package org.picketlink.test.identity.federation.bindings.wildfly.rest;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.DatatypeConverter;

import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import io.undertow.servlet.api.WebResourceCollection;
import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import io.undertow.servlet.api.DeploymentInfo;
import org.picketlink.identity.federation.bindings.wildfly.rest.SAMLOauthInfoBodyReader;
import org.picketlink.test.identity.federation.bindings.wildfly.TestClassIntrospector;
import org.picketlink.test.identity.federation.bindings.wildfly.TestIdentityManager;

/**
 * Base class for the REST Based Tests on Undertow using RESTEasy
 * @author Anil Saldhana
 * @since June 16, 2014
 */
public abstract class UndertowJaxrsBaseTest {
    protected static final String server_url = "http://localhost:8080";

    protected static UndertowJaxrsServer server;

    protected DeploymentInfo deploymentInfo;

    @BeforeClass
    public static void init() throws Exception {
        System.setProperty("org.jboss.resteasy.port", "8080");

        server = new UndertowJaxrsServer().start();
    }

    @AfterClass
    public static void stop() throws Exception {
        server.stop();
    }

    @Before
    public void setup() throws Exception{
        deploymentInfo = deployApplication();
        server.deploy(deploymentInfo);
    }

    public DeploymentInfo deployApplication() throws Exception {
        TestIdentityManager identityManager = new TestIdentityManager();
        identityManager.addUser("user1", "password1", "role1");

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
        return di;
    }

    public Client restClient(String user, String pass) throws Exception{
        Client client = ClientBuilder.newClient();
        client.register(new Authenticator(user,pass));
        client.register(new SAMLOauthInfoBodyReader());
        return client;
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
