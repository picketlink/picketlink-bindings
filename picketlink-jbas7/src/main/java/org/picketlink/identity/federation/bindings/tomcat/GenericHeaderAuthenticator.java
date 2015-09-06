package org.picketlink.identity.federation.bindings.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JBAS-2283: Provide custom header based authentication support
 *
 * Header Authenticator that deals with userid from the request header Requires two attributes configured on the Tomcat Service -
 * one for the http header denoting the authenticated identity and the other is the SESSION cookie
 *
 * @author Anil Saldhana
 * @author Stefan Guilhen
 * @version $Revision$
 * @since Sep 11, 2006
 */
public class GenericHeaderAuthenticator extends AbstractGenericHeaderAuthenticator {

    public boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
        return super.performAuthentication(request, (Response) response, config);
    }
}
