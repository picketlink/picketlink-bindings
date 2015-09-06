package org.picketlink.test.identity.federation.bindings.util;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import junit.framework.TestCase;

import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.util.SignatureUtil;
import org.picketlink.identity.federation.core.util.KeyStoreUtil;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.web.util.RedirectBindingSignatureUtil;

/**
 * Unit Test the redirect binding sig util
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 13, 2009
 */
public class RedirectBindingSignatureUtilTestCase extends TestCase {
    /**
     * Test the encoding/decoding of a SAML2 AuthnRequest with signature support
     *
     * @throws Exception
     */
    public void testSigUseCase() throws Exception {
        SAML2Request samlRequest = new SAML2Request();

        AuthnRequestType authnRequest = samlRequest.createAuthnRequestType(IDGenerator.create("ID_"), "http://sp",
                "http://idp", "http://sp");

        KeyPair kp = KeyStoreUtil.generateKeyPair("RSA");

        PrivateKey signingKey = kp.getPrivate();

        String sigURL = RedirectBindingSignatureUtil.getSAMLRequestURLWithSignature(authnRequest, null, signingKey);

        // At this time, the sigURL contains the signed request and the signature

        // Let us do the processing at the receiving end
        byte[] sigValue = RedirectBindingSignatureUtil.getSignatureValueFromSignedURL(sigURL);

        // Construct the url again
        String reqFromURL = RedirectBindingSignatureUtil.getTokenValue(sigURL, "SAMLRequest");
        String relayStateFromURL = RedirectBindingSignatureUtil.getTokenValue(sigURL, "RelayState");
        String sigAlgFromURL = RedirectBindingSignatureUtil.getTokenValue(sigURL, "SigAlg");

        StringBuilder sb = new StringBuilder();
        sb.append("SAMLRequest=").append(reqFromURL);

        if (relayStateFromURL != null && relayStateFromURL.length() > 0) {
            sb.append("&RelayState=").append(relayStateFromURL);
        }
        sb.append("&SigAlg=").append(sigAlgFromURL);

        PublicKey validatingKey = kp.getPublic();
        boolean isValid = SignatureUtil.validate(sb.toString().getBytes("UTF-8"), sigValue, validatingKey);

        assertTrue(isValid);
    }
}
