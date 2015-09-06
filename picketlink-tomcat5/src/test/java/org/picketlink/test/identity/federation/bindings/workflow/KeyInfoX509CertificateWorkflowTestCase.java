package org.picketlink.test.identity.federation.bindings.workflow;

import org.junit.Ignore;
import org.junit.Test;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.bindings.tomcat.idp.IDPWebBrowserSSOValve;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.test.identity.federation.bindings.authenticators.AuthenticatorTestUtils;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaRequest;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaResponse;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.InputStream;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

/**
 * PLINK-350: Validate the XMLSignatureUtil->KeyInfo/X509Certificate Feature from PLINK-146
 *
 * @author Anil Saldhana
 * @since January 13, 2014
 */
@Ignore
public class KeyInfoX509CertificateWorkflowTestCase extends SAML2RedirectSignatureTomcatWorkflowUnitTestCase{

    //We provide a different picketlink.xml for the IDP which has the X509CERTIFICATE auth key value
    protected IDPWebBrowserSSOValve createIdentityProvider() {
        return AuthenticatorTestUtils.createIdentityProvider(BASE_PROFILE + "/idp-sig-keyinfo/");
    }

    @Test
    public void testSAML2RedirectWithSameConsumerAndProvider() throws Exception {
        //Empty
    }

    /**
     * Tests the token's signatures validations when the requester is in a different host than the SP and IDP. <br/>
     * The keyprovider is configured with a ValidatingAlias for a specific SP (192.168.1.2) that is different from the IDP
     * (192.168.1.1) and the user (192.168.1.3). <br/>
     * Test fails if:
     * <ul>
     * <li>If you change the IDP address the test will fail because the SP's keystore and
     * SPRedirectSignatureFormAuthenticator.idpAddress is configured to use a validating alias with value 192.168.1.1.</li>
     * <li>If you change the SP address (SP_PROFILE/WEB-INF/picketlink-idfed.xml) the test will fail because the IDP's keystore
     * is only configured to use a validating alias with value 192.168.1.2.</li>
     * <li>If you omit the SPRedirectSignatureFormAuthenticator.idpAddress because the user's address will be used to validate
     * the token. His address is not in the keystore.</li>
     * <li>If you omit the IDPWebBrowserSSOValve.validatingAliasToTokenIssuer because the user's address will be used to
     * validate the token. His address is not in the keystore.</li>
     * </ul>
     */
    @Test
    public void testSAML2RedirectWithDifferentConsumerAndProvider() throws Exception {
        testWorkflow("192.168.1.3", "192.168.1.1");
    }

    protected void testWorkflow(String userAddress, String idpAddress) throws Exception {
        System.setProperty("picketlink.schema.validate", "false");
        MockCatalinaRequest request = AuthenticatorTestUtils.createRequest(userAddress, false);

        // Sends a initial request to the SP. Requesting a resource ...
        MockCatalinaResponse idpAuthRequest = sendSPRequest(request, false, idpAddress);

        assertNotNull("Redirect String can not be null.", idpAuthRequest.redirectString);

        // Sends a auth request to the IDP
        request = AuthenticatorTestUtils.createRequest(userAddress, true);

        setQueryStringFromResponse(idpAuthRequest, request);

        MockCatalinaResponse idpAuthResponse = sendIDPRequest(request);

        assertNotNull("Redirect String can not be null.", idpAuthResponse.redirectString);
        
        //Ensure that the IDP response has the X509 Certificate in the keyinfo
        String responseSAMLResponse = AuthenticatorTestUtils.getSAMLResponse(idpAuthResponse.redirectString);

        InputStream dataStream = RedirectBindingUtil.urlBase64DeflateDecode(responseSAMLResponse);
        SAML2Response saml2Response = new SAML2Response();
        SAML2Object saml2Object = saml2Response.getSAML2ObjectFromStream(dataStream);
        assertNotNull(saml2Object);
        ResponseType responseType = (ResponseType) saml2Object;
        Element domElement = responseType.getSignature();
        Element keyInfo = (Element) domElement.getElementsByTagName("dsig:KeyInfo").item(0);
        Node firstChild = keyInfo.getFirstChild();
        assertTrue(firstChild.getNodeName().indexOf("X509Data") > -1);

        // Sends the IDP response to the SP. Now the user is succesfully authenticated and access for the requested resource is
        // granted...
        request = AuthenticatorTestUtils.createRequest(userAddress, false);

        setQueryStringFromResponse(idpAuthResponse, request);

        sendSPRequest(request, true, idpAddress);
    }
}
