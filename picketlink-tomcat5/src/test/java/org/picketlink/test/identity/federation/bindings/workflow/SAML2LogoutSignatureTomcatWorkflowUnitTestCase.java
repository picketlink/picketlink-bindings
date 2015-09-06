package org.picketlink.test.identity.federation.bindings.workflow;

import junit.framework.Assert;
import org.apache.catalina.LifecycleException;
import org.junit.Before;
import org.junit.Test;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.bindings.tomcat.idp.IDPWebBrowserSSOValve;
import org.picketlink.identity.federation.bindings.tomcat.sp.SPRedirectSignatureFormAuthenticator;
import org.picketlink.identity.federation.web.core.SessionManager;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContext;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaLoginConfig;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRequest;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaResponse;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaSession;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * <p>
 * Unit test the SAML2 Logout Mechanism for Tomcat bindings with token signature.</>
 * <p>
 * This test uses a scenario where there are two SPs (Employee e Sales) pointing to the same IDP. When the user sends a GLO
 * logout request to the Employee SP Picketlink will start the logout process and invalidate the user in both SPs.
 * </p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @since Dec 1, 2011
 */
@SuppressWarnings("unused")
public class SAML2LogoutSignatureTomcatWorkflowUnitTestCase extends AbstractSAML2RedirectWithSignatureTestCase {
    private static final String SP_SALES_URL = "http://192.168.1.4:8080/sales/";

    private static final String SP_SALES_PROFILE = BASE_PROFILE + "/sp/sales-sig";

    private static final String SP_EMPLOYEE_URL = "http://192.168.1.2:8080/employee/";

    private static final String SP_EMPLOYEE_PROFILE = BASE_PROFILE + "/sp/employee-sig";

    private IDPWebBrowserSSOValve idpWebBrowserSSOValve;

    private MockCatalinaSession employeeHttpSession = new MockCatalinaSession();

    private MockCatalinaSession salesHttpSession = new MockCatalinaSession();

    private SPRedirectSignatureFormAuthenticator salesServiceProvider;

    private SPRedirectSignatureFormAuthenticator employeeServiceProvider;

    @Before
    public void onBefore() {
        this.employeeHttpSession.setServletContext(new MockCatalinaContext());
        this.salesHttpSession.setServletContext(new MockCatalinaContext());
    }

    /**
     * Tests the GLO logout mechanism.
     *
     * @throws LifecycleException
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testSAML2LogOutFromSP() throws LifecycleException, IOException, ServletException {
        System.setProperty("picketlink.schema.validate", "false");
        // requests a GLO logout to the Employee SP
        MockCatalinaRequest originalEmployeeLogoutRequest = createRequest(employeeHttpSession, true);

        originalEmployeeLogoutRequest.setParameter(GeneralConstants.GLOBAL_LOGOUT, "true");

        MockCatalinaResponse originalEmployeeLogoutResponse = sendSPRequest(originalEmployeeLogoutRequest,
                getEmployeeServiceProvider(), this.salesHttpSession);

        assertNotNull(originalEmployeeLogoutResponse);

        // sends the LogoutRequest to the IDP
        MockCatalinaRequest idpLogoutRequest = createIDPRequest(true);

        setQueryStringFromResponse(originalEmployeeLogoutResponse, idpLogoutRequest);

        MockCatalinaResponse idpLogoutResponse = sendIDPRequest(idpLogoutRequest);

        // The IDP responds with a LogoutRequest. Send it to the Sales SP with the RelayState pointing to the Employee SP
        MockCatalinaRequest salesLogoutRequest = createRequest(salesHttpSession, true);

        setQueryStringFromResponse(idpLogoutResponse, salesLogoutRequest);

        MockCatalinaResponse salesLogoutResponse = sendSPRequest(salesLogoutRequest, getSalesServiceProvider(), this.salesHttpSession);

        // At this moment the user is not logged in Sales SP anymore.
        assertTrue(this.salesHttpSession.isInvalidated());

        // sends the StatusResponse to the IDP to continue the logout process.
        MockCatalinaRequest processSalesStatusResponse = createIDPRequest(true);

        setQueryStringFromResponse(salesLogoutResponse, processSalesStatusResponse);

        MockCatalinaResponse salesStatusResponse = sendIDPRequest(processSalesStatusResponse);

        // The IDP responds with a LogoutRequest. Send it to the Employee SP.
        MockCatalinaRequest employeeLogoutRequest = createRequest(employeeHttpSession, true);

        setQueryStringFromResponse(salesStatusResponse, employeeLogoutRequest);

        MockCatalinaResponse employeeLogoutResponse = sendSPRequest(employeeLogoutRequest, getEmployeeServiceProvider(), this.employeeHttpSession);

        // At this moment the user is not logged in Employee SP anymore.
        assertTrue(this.employeeHttpSession.isInvalidated());

        Assert.assertNotNull(employeeLogoutRequest.getForwardPath());
        Assert.assertEquals(employeeLogoutRequest.getForwardPath(), GeneralConstants.LOGOUT_PAGE_NAME);
        assertEquals(0, getIdentityServer(getIDPWebBrowserSSOValve()).stack().getParticipants(getIDPHttpSession().getId()));
        assertEquals(0,
                getIdentityServer(getIDPWebBrowserSSOValve()).stack()
                        .getNumOfParticipantsInTransit(getIDPHttpSession().getId()));

        // Finally the session should be invalidated
        assertTrue(getIDPHttpSession().isInvalidated());
    }

    private MockCatalinaResponse sendSPRequest(MockCatalinaRequest request, SPRedirectSignatureFormAuthenticator sp, MockCatalinaSession session)
            throws LifecycleException, IOException, ServletException {
        MockCatalinaResponse response = new MockCatalinaResponse();
        response.setWriter(new PrintWriter(new ByteArrayOutputStream()));

        ServletContext servletContext = (ServletContext) sp.getContainer();

        session.setServletContext(servletContext);

        SessionManager sessionManager = SessionManager.get(servletContext);

        sessionManager.add(request.getPrincipal(), session);

        sp.authenticate(request, response, new MockCatalinaLoginConfig());

        return response;
    }

    @SuppressWarnings("deprecation")
    private MockCatalinaResponse sendIDPRequest(MockCatalinaRequest request) throws LifecycleException, IOException,
            ServletException {
        IDPWebBrowserSSOValve idp = getIDPWebBrowserSSOValve();

        MockCatalinaSession session = (MockCatalinaSession) request.getSession(false);

        session.setServletContext((MockCatalinaContext) idp.getContainer());

        idp.setStrictPostBinding(false);

        MockCatalinaResponse response = new MockCatalinaResponse();

        response.setWriter(new PrintWriter(new ByteArrayOutputStream()));

        idp.invoke(request, response);

        ((MockCatalinaSession) request.getSession()).clear();

        return response;
    }

    private IDPWebBrowserSSOValve getIDPWebBrowserSSOValve() throws LifecycleException {
        if (this.idpWebBrowserSSOValve == null) {
            this.idpWebBrowserSSOValve = createIdentityProvider();
            addIdentityServerParticipants(this.idpWebBrowserSSOValve, SP_EMPLOYEE_URL);
            addIdentityServerParticipants(this.idpWebBrowserSSOValve, SP_SALES_URL);
        }

        return this.idpWebBrowserSSOValve;
    }

    public SPRedirectSignatureFormAuthenticator getEmployeeServiceProvider() {
        if (this.employeeServiceProvider == null) {
            this.employeeServiceProvider = (SPRedirectSignatureFormAuthenticator) createServiceProvider(SP_EMPLOYEE_PROFILE);
        }

        return this.employeeServiceProvider;
    }

    public SPRedirectSignatureFormAuthenticator getSalesServiceProvider() {
        if (this.salesServiceProvider == null) {
            this.salesServiceProvider = (SPRedirectSignatureFormAuthenticator) createServiceProvider(SP_SALES_PROFILE);
        }

        return this.salesServiceProvider;
    }
}
