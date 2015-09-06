package org.picketlink.identity.federation.bindings.util;

import java.io.IOException;
import java.net.URL;

/**
 * Util for tomcat valves
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 22, 2009
 */
public class ValveUtil {

    /**
     * Given a SP or IDP issuer from the assertion, return the host
     *
     * @param domainURL
     *
     * @return
     *
     * @throws IOException
     */
    public static String getDomain(String domainURL) throws IOException {
        URL url = new URL(domainURL);
        return url.getHost();
    }
}
