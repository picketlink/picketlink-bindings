package org.picketlink.test.identity.federation.bindings.workflow;

import org.apache.catalina.deploy.LoginConfig;
import org.junit.Test;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.bindings.tomcat.sp.SPPostFormAuthenticator;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContext;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContextClassLoader;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRequest;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaResponse;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaSession;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Validating PicketLink SP Handling of a response from Ping Federate IDP.
 *
 * @author Anil.Saldhana@redhat.com
 * @since Feb 22, 2011
 */
public class PingFederateResponseTestCase {
    private final String profile = "saml2/post";

    private final ClassLoader tcl = Thread.currentThread().getContextClassLoader();

    @SuppressWarnings("unchecked")
    @Test
    public void testSP() throws Exception {
        System.setProperty("picketlink.schema.validate", "false");
        // First we go to the employee application
        MockCatalinaContextClassLoader mclSPEmp = setupTCL(profile + "/ping");
        Thread.currentThread().setContextClassLoader(mclSPEmp);
        SPPostFormAuthenticator spEmpl = new SPPostFormAuthenticator();

        MockCatalinaContext context = new MockCatalinaContext();

        spEmpl.setContainer(context);
        spEmpl.testStart();

        MockCatalinaSession session = new MockCatalinaSession();

        session.setServletContext(context);

        MockCatalinaRequest catalinaRequest = new MockCatalinaRequest();

        catalinaRequest.setSession(session);

        catalinaRequest.setSession(session);
        catalinaRequest.setContext(context);
        catalinaRequest.setMethod("POST");

        String idpResponse = PostBindingUtil.base64Encode(new String(readIDPResponse()));

        catalinaRequest.setParameter(GeneralConstants.SAML_RESPONSE_KEY, idpResponse);

        MockCatalinaResponse catalinaResponse = new MockCatalinaResponse();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        catalinaResponse.setWriter(new PrintWriter(baos));

        LoginConfig loginConfig = new LoginConfig();
        assertTrue(spEmpl.authenticate(catalinaRequest, catalinaResponse, loginConfig));

        Map<String, List<Object>> sessionMap = (Map<String, List<Object>>) session
                .getAttribute(GeneralConstants.SESSION_ATTRIBUTE_MAP);
        assertNotNull(sessionMap);
        assertEquals("asptest_email", sessionMap.get("email").get(0));
        assertEquals("asptest_zipcode", sessionMap.get("zipcode").get(0));
    }

    private byte[] readIDPResponse() throws IOException {
        File file = new File(tcl.getResource("responseIDP/pingidp.xml").getPath());
        InputStream is = new FileInputStream(file);
        assertNotNull(is);

        long length = file.length();

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }

    private MockCatalinaContextClassLoader setupTCL(String resource) {
        URL[] urls = new URL[] { tcl.getResource(resource) };

        MockCatalinaContextClassLoader mcl = new MockCatalinaContextClassLoader(urls);
        mcl.setDelegate(tcl);
        mcl.setProfile(resource);
        return mcl;
    }
}
