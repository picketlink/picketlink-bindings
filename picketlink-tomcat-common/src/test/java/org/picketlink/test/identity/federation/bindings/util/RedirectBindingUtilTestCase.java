package org.picketlink.test.identity.federation.bindings.util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringWriter;

import junit.framework.TestCase;

import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;

/**
 * Unit Test the RedirectBindingUtil
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 15, 2009
 */
public class RedirectBindingUtilTestCase extends TestCase {
    /**
     * Test the encoding/decoding of a SAML2 AuthnRequest
     *
     * @throws Exception
     */
    public void testRegularRedirectBindingUseCaseWithStringWriter() throws Exception {
        AuthnRequestType authnRequest = (new SAML2Request()).createAuthnRequestType(IDGenerator.create("ID_"), "http://sp",
                "http://idp", "http://sp");

        StringWriter sw = new StringWriter();
        SAML2Request saml2Request = new SAML2Request();
        saml2Request.marshall(authnRequest, sw);

        String request = RedirectBindingUtil.deflateBase64URLEncode(sw.toString());

        InputStream is = RedirectBindingUtil.urlBase64DeflateDecode(request);

        RequestAbstractType parsed = saml2Request.getRequestType(is);
        assertNotNull("Parsed request is not null", parsed);
        assertTrue("AuthnRequestType", parsed instanceof AuthnRequestType);
    }

    /**
     * Test the encoding/decoding of a SAML2 AuthnRequest (Use of ByteArrayOutputStream)
     *
     * @throws Exception
     */
    public void testRegularRedirectBindingUseCaseWithByteArray() throws Exception {
        AuthnRequestType authnRequest = (new SAML2Request()).createAuthnRequestType(IDGenerator.create("ID_"), "http://sp",
                "http://idp", "http://sp");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        SAML2Request saml2Request = new SAML2Request();
        saml2Request.marshall(authnRequest, baos);

        String request = RedirectBindingUtil.deflateBase64URLEncode(baos.toByteArray());

        InputStream is = RedirectBindingUtil.urlBase64DeflateDecode(request);

        AuthnRequestType parsed = saml2Request.getAuthnRequestType(is);
        assertNotNull("Parsed request is not null", parsed);
    }
}
