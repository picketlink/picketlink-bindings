package org.picketlink.test.identity.federation.bindings.workflow;

import junit.framework.TestCase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.bindings.tomcat.idp.IDPWebBrowserSSOValve;
import org.picketlink.identity.federation.bindings.tomcat.sp.SPRedirectFormAuthenticator;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContext;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContextClassLoader;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaLoginConfig;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRealm;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRequest;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaResponse;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaSession;

import javax.servlet.ServletException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit test for the Workflow for the SAML2 Redirect Binding
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 20, 2009
 */
public class SAML2RedirectTomcatWorkflowUnitTestCase extends TestCase {
    private String profile = "saml2/redirect";
    private ClassLoader tcl = Thread.currentThread().getContextClassLoader();
    private String employee = "http://localhost:8080/employee/";

    private String SAML_REQUEST_KEY = "SAMLRequest=";

    private String SAML_RESPONSE_KEY = "SAMLResponse=";

    @SuppressWarnings("deprecation")
    public void testSAML2Redirect() throws Exception {
        System.setProperty("picketlink.schema.validate", "false");
        MockCatalinaContextClassLoader mclSPEmp = setupTCL(profile + "/sp/employee");
        Thread.currentThread().setContextClassLoader(mclSPEmp);

        SPRedirectFormAuthenticator sp = new SPRedirectFormAuthenticator();

        MockCatalinaContext context = new MockCatalinaContext();
        MockCatalinaRequest request = new MockCatalinaRequest();

        request.setParameter(GeneralConstants.RELAY_STATE, null);

        MockCatalinaResponse response = new MockCatalinaResponse();
        MockCatalinaLoginConfig loginConfig = new MockCatalinaLoginConfig();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        response.setWriter(new PrintWriter(baos));

        MockCatalinaSession session = new MockCatalinaSession();

        session.setServletContext(context);

        sp.setContainer(context);
        sp.testStart();

        sp.authenticate(request, response, loginConfig);

        String redirectStr = response.redirectString;
        assertNotNull("Redirect String is null?", redirectStr);
        String saml = redirectStr.substring(redirectStr.indexOf(SAML_REQUEST_KEY) + SAML_REQUEST_KEY.length());

        // Now send it to IDP
        MockCatalinaRealm realm = new MockCatalinaRealm("anil", "test", new Principal() {
            public String getName() {
                return "anil";
            }
        });

        List<String> roles = new ArrayList<String>();
        roles.add("manager");
        roles.add("employee");

        MockCatalinaContextClassLoader mclIDP = setupTCL(profile + "/idp/");
        Thread.currentThread().setContextClassLoader(mclIDP);

        request = new MockCatalinaRequest();
        request.setRemoteAddr(employee);
        request.setSession(session);
        request.setParameter("SAMLRequest", RedirectBindingUtil.urlDecode(saml));
        request.setUserPrincipal(new GenericPrincipal(realm, "anil", "test", roles));
        request.setMethod("GET");

        response = new MockCatalinaResponse();
        response.setWriter(new PrintWriter(baos));

        IDPWebBrowserSSOValve idp = createIdpAuthenticator();

        idp.setSignOutgoingMessages(false);
        idp.setIgnoreIncomingSignatures(true);
        idp.setStrictPostBinding(false);

        idp.setContainer(context);
        idp.start();
        idp.invoke(request, response);

        redirectStr = response.redirectString;
        assertNotNull(redirectStr);
        String samlResponse = RedirectBindingUtil.urlDecode(redirectStr.substring(redirectStr.indexOf(SAML_RESPONSE_KEY)
                + SAML_RESPONSE_KEY.length()));

        mclSPEmp = setupTCL(profile + "/sp/employee");
        Thread.currentThread().setContextClassLoader(mclSPEmp);

        sp = new SPRedirectFormAuthenticator();
        context = new MockCatalinaContext();

        context.setRealm(realm);
        request = new MockCatalinaRequest();
        request.setContext(context);

        request.setMethod("GET");
        request.setParameter("SAMLResponse", samlResponse);
        request.setParameter("RelayState", null);
        request.setSession(session);

        response = new MockCatalinaResponse();
        loginConfig = new MockCatalinaLoginConfig();

        sp.setContainer(context);
        sp.testStart();
        sp.getConfiguration().setIdpUsesPostBinding(false);

        assertTrue("Employee app auth success", sp.authenticate(request, response, loginConfig));
    }

    private IDPWebBrowserSSOValve createIdpAuthenticator() {
        IDPWebBrowserSSOValve idpWebBrowserSSOValve = new IDPWebBrowserSSOValve();

        idpWebBrowserSSOValve.setNext(new ValveBase() {
            @Override
            public void invoke(Request request, Response response) throws IOException, ServletException {

            }
        });

        return idpWebBrowserSSOValve;
    }

    private MockCatalinaContextClassLoader setupTCL(String resource) {
        URL[] urls = new URL[] { tcl.getResource(resource) };

        MockCatalinaContextClassLoader mcl = new MockCatalinaContextClassLoader(urls);
        mcl.setDelegate(tcl);
        mcl.setProfile(resource);
        return mcl;
    }
}
