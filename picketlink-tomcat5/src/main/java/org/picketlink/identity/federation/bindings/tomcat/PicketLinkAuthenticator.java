package org.picketlink.identity.federation.bindings.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;

import java.io.IOException;
import java.security.Principal;

/**
 * An authenticator that delegates actual authentication to a realm, and in turn to a security manager, by presenting a
 * "conventional" identity. The security manager must accept the conventional identity and generate the real identity for the
 * authenticated principal.
 *
 * @author <a href="mailto:ovidiu@novaordis.com">Ovidiu Feodorov</a>
 * @author Anil.Saldhana@redhat.com
 * @since Apr 11, 2011
 */
public class PicketLinkAuthenticator extends AbstractPicketLinkAuthenticator {

    public PicketLinkAuthenticator() {
        logger.trace("PicketLinkAuthenticator Created");
    }

    @Override
    protected boolean authenticate(Request request, Response response, LoginConfig loginConfig) throws IOException {
        return super.performAuthentication(request, response, loginConfig);
    }

    @Override
    protected void doRegister(Request request, Response response, Principal principal, String password) {
        register(request, response, principal, this.authMethod, principal.getName(), password);
    }
}
