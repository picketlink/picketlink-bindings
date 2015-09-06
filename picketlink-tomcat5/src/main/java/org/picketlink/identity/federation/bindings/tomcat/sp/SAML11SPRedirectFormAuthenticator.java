package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.LifecycleException;

/**
 * Authenticator for SAML 1.1 processing at the Service Provider
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jul 7, 2011
 */
public class SAML11SPRedirectFormAuthenticator extends AbstractSAML11SPRedirectFormAuthenticator {

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.bindings.tomcat.sp.BaseFormAuthenticator#start()
     */
    @Override
    public void start() throws LifecycleException {
        super.start();
        startPicketLink();
    }

    public void testStart() throws LifecycleException {
        super.testStart();
        startPicketLink();
    }

    @Override
    protected String getContextPath() {
        return getContext().getServletContext().getContextPath();
    }
}
