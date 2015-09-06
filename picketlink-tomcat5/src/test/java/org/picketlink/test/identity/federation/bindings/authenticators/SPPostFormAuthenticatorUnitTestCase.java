package org.picketlink.test.identity.federation.bindings.authenticators;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URL;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.picketlink.identity.federation.bindings.tomcat.sp.SPPostFormAuthenticator;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContext;
import org.picketlink.test.identity.federation.bindings.mock.MockCatalinaContextClassLoader;

/**
 * Unit test the {@link SPPostFormAuthenticator}
 *
 * @author Anil.Saldhana@redhat.com
 * @since Mar 1, 2011
 */
public class SPPostFormAuthenticatorUnitTestCase {
    @Test
    public void testIDPMetadataFile() throws Exception {
        System.setProperty("picketlink.schema.validate", "false");
        MockCatalinaContext ctx = new MockCatalinaContext();
        SPPostFormAuthenticator auth = new SPPostFormAuthenticator();
        auth.setContainer(ctx);

        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        URL configURL = tccl.getResource("config/test-idp-metadata-file-config.xml");
        URL[] urls = new URL[] { configURL };
        MockCatalinaContextClassLoader tcl = new MockCatalinaContextClassLoader(urls);
        tcl.associate("/WEB-INF/picketlink-idfed.xml", configURL.openStream());
        tcl.associate("/WEB-INF/picketlink-handlers.xml",
                tccl.getResourceAsStream("saml2/post/sp/employee/WEB-INF/picketlink-handlers.xml"));
        tcl.associate("/WEB-INF/testshib.org.idp-metadata.xml",
                tccl.getResourceAsStream("metadata/testshib.org.idp-metadata.xml"));
        tcl.setProfile("DUMMY");
        tcl.setDelegate(tccl);

        Thread.currentThread().setContextClassLoader(tcl);
        auth.testStart();
        assertEquals("https://idp.testshib.org/idp/profile/SAML2/POST/SSO", auth.getIdentityURL());
        X509Certificate idpCert = auth.getIdpCertificate();
        assertNotNull(idpCert);
        assertEquals("CN=idp.testshib.org, O=TestShib, L=Pittsburgh, ST=Pennsylvania, C=US", idpCert.getIssuerDN().getName());
    }
}
