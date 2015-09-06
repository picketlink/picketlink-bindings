package org.picketlink.test.identity.federation.bindings.util;

import junit.framework.TestCase;

import org.picketlink.identity.federation.bindings.util.ValveUtil;

/**
 * Unit tests for the ValveUtil
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 26, 2009
 */
public class ValveUtilUnitTestCase extends TestCase {
    /**
     * Given an issuer url, retrieve the host
     *
     * @throws Exception
     */
    public void testTrustedDomain() throws Exception {
        String issuerURL = "http://localhost:8080/sp";
        String issuer = ValveUtil.getDomain(issuerURL);
        assertEquals("localhost", "localhost", issuer);

        issuerURL = "http://192.168.0.1/idp";
        issuer = ValveUtil.getDomain(issuerURL);
        assertEquals("192.168.0.1", "192.168.0.1", issuer);
    }
}
