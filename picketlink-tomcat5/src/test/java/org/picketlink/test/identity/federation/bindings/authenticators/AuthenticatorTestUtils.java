
package org.picketlink.test.identity.federation.bindings.authenticators;

import junit.framework.Assert;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.bindings.tomcat.idp.IDPWebBrowserSSOValve;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContext;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContextClassLoader;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRealm;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRequest;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaSession;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 *
 */
public class AuthenticatorTestUtils {

    public static IDPWebBrowserSSOValve createIdentityProvider(String baseClassLoaderPath) {
        Thread.currentThread().setContextClassLoader(createContextClassLoader(baseClassLoaderPath));

        IDPWebBrowserSSOValve idpWebBrowserSSOValve = new IDPWebBrowserSSOValve();

        idpWebBrowserSSOValve.setNext(new ValveBase() {
            @Override
            public void invoke(Request request, Response response) throws IOException, ServletException {

            }
        });

        MockCatalinaContext catalinaContext = new MockCatalinaContext();

        idpWebBrowserSSOValve.setContainer(catalinaContext);

        try {
            idpWebBrowserSSOValve.start();
        } catch (LifecycleException e) {
            e.printStackTrace();
        }

        return idpWebBrowserSSOValve;
    }

    public static MockCatalinaContextClassLoader createContextClassLoader(String resource) {
        URL[] urls = new URL[]

        { Thread.currentThread().getContextClassLoader().getResource(resource) };

        MockCatalinaContextClassLoader mcl = new MockCatalinaContextClassLoader(urls);

        mcl.setDelegate(Thread.currentThread().getContextClassLoader());
        mcl.setProfile(resource);

        return mcl;
    }

    public static MockCatalinaRequest createRequest(String userAddress, boolean withUserPrincipal) {
        MockCatalinaRequest request = new MockCatalinaRequest();

        request = new MockCatalinaRequest();
        request.setMethod("GET");
        request.setRemoteAddr(userAddress);
        MockCatalinaContext context = new MockCatalinaContext();
        request.setParameter(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY, "");
        request.setContext(context);

        MockCatalinaSession session = new MockCatalinaSession();

        session.setServletContext(context);

        request.setSession(session);

        if (withUserPrincipal) {
            request.setUserPrincipal(createPrincipal());
        }

        return request;
    }

    public static GenericPrincipal createPrincipal() {
        MockCatalinaRealm realm = new MockCatalinaRealm("user", "user", new Principal() {
            public String getName() {
                return "user";
            }
        });
        List<String> roles = new ArrayList<String>();
        roles.add("manager");
        roles.add("employee");

        List<String> rolesList = new ArrayList<String>();
        rolesList.add("manager");

        return new GenericPrincipal(realm, "user", "user", roles);
    }

    public static void populateParametersWithQueryString(String queryString, MockCatalinaRequest request) {
        String samlParameter = null;
        String samlParameterValue = null;

        if (queryString.contains(GeneralConstants.SAML_REQUEST_KEY + "=")) {
            samlParameter = GeneralConstants.SAML_REQUEST_KEY;
            samlParameterValue = getSAMLRequest(queryString);
        } else {
            samlParameter = GeneralConstants.SAML_RESPONSE_KEY;
            samlParameterValue = getSAMLResponse(queryString);
        }

        try {
            request.setParameter(samlParameter, RedirectBindingUtil.urlDecode(samlParameterValue));

            boolean hasRelayState = queryString.indexOf("&RelayState") != -1;

            if (hasRelayState) {
                request.setParameter(GeneralConstants.RELAY_STATE,
                        RedirectBindingUtil.urlDecode(getSAMLRelayState(queryString)));
            }

            request.setParameter(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY,
                    RedirectBindingUtil.urlDecode(getSAMLSigAlg(queryString)));
            request.setParameter(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY,
                    RedirectBindingUtil.urlDecode(getSAMLSignature(queryString)));

            request.setQueryString(queryString.toString());

        } catch (Exception e) {
            Assert.fail("Erro while populating request with SAML parameters.");
        }
    }

    public static final  String getSAMLResponse(String queryString) {
        int endIndex = queryString.indexOf("&SigAlg=");

        if (queryString.contains("&RelayState=")) {
            endIndex = queryString.indexOf("&RelayState=");
        }

        // no signature info
        if (endIndex == -1) {
            endIndex = queryString.length();
        }

        return queryString.substring(queryString.indexOf(GeneralConstants.SAML_RESPONSE_KEY + "=")
                + (GeneralConstants.SAML_RESPONSE_KEY + "=").length(), endIndex);
    }

    public static final  String getSAMLSignature(String queryString) {
        return queryString.substring(queryString.indexOf("&Signature=") + "&Signature=".length());
    }

    public static final  String getSAMLRelayState(String queryString) {
        return queryString.substring(queryString.indexOf("&RelayState=") + "&RelayState=".length(),
                queryString.lastIndexOf("&SigAlg="));
    }

    public static final  String getSAMLSigAlg(String queryString) {
        int indexOfSigAlg = queryString.indexOf("&SigAlg=");

        // no signature info
        if (indexOfSigAlg == -1) {
            return "";
        }

        return queryString.substring(indexOfSigAlg + "&SigAlg=".length(),
                queryString.lastIndexOf("&Signature="));
    }

    public static final  String getSAMLRequest(String queryString) {
        int endIndex = queryString.indexOf("&SigAlg=");

        if (queryString.contains("&RelayState=")) {
            endIndex = queryString.indexOf("&RelayState=");
        }

        return queryString.substring(queryString.indexOf(GeneralConstants.SAML_REQUEST_KEY + "=")
                + (GeneralConstants.SAML_REQUEST_KEY + "=").length(), endIndex);
    }


}
