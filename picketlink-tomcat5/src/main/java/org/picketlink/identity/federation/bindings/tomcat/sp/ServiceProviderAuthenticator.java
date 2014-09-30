package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.LifecycleException;

/**
 * Unified Service Provider Authenticator
 *
 * @author anil saldhana
 */
public class ServiceProviderAuthenticator extends AbstractSPFormAuthenticator {

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

    @Override
    public void stop() throws LifecycleException {
        super.stop();
        stopPicketLink();
    }

    @Override
    protected String getContextPath() {
        return getContext().getServletContext().getContextPath();
    }
}