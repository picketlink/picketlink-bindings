package org.picketlink.identity.federation.bindings.tomcat.sp;

/**
 * Tomcat Authenticator for the HTTP/Redirect binding with Signature support
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 12, 2009
 */
public class SPRedirectSignatureFormAuthenticator extends SPRedirectFormAuthenticator {

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.bindings.tomcat.sp.AbstractSPFormAuthenticator#doSupportSignature()
     */
    @Override
    protected boolean doSupportSignature() {
        return true;
    }
}
