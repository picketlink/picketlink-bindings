package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.LifecycleException;

/**
 * Authenticator at the Service Provider that handles HTTP/Redirect binding of SAML 2 but falls back on Form Authentication
 *
 * @author Anil.Saldhana@redhat.com
 * @since Dec 12, 2008
 */
public class SPRedirectFormAuthenticator extends ServiceProviderAuthenticator {

    @Override
    protected String getContextPath() {
        return getContext().getServletContext().getContextPath();
    }

    @Override
    protected void startPicketLink() throws LifecycleException {
        super.startPicketLink();
        getConfiguration().setBindingType("REDIRECT");
    }
}
