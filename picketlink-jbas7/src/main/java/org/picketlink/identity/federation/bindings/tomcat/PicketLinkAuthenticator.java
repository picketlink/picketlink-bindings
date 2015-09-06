package org.picketlink.identity.federation.bindings.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

/**
 * An authenticator that delegates actual authentication to a realm, and in turn to a security manager, by presenting a
 * "conventional" identity. The security manager must accept the conventional identity and generate the real identity for the
 * authenticated principal.
 *
 * @author <a href="mailto:ovidiu@novaordis.com">Ovidiu Feodorov</a>
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 * @since Apr 11, 2011
 */
public class PicketLinkAuthenticator extends AbstractPicketLinkAuthenticator {

    /* (non-Javadoc)
     * @see org.apache.catalina.authenticator.AuthenticatorBase#authenticate(org.apache.catalina.connector.Request, javax.servlet.http.HttpServletResponse, org.apache.catalina.deploy.LoginConfig)
     */
    @Override
    protected boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
        return super.performAuthentication(request, (Response) response, config);
    }

    /* (non-Javadoc)
     * @see org.picketlink.identity.federation.bindings.tomcat.AbstractPicketLinkAuthenticator#doRegister(org.apache.catalina.connector.Request, org.apache.catalina.connector.Response, java.security.Principal, java.lang.String)
     */
    @Override
    protected void doRegister(Request request, Response response, Principal principal, String password) {
        register(request, response, principal, this.authMethod, principal.getName(), password);
    }
}
