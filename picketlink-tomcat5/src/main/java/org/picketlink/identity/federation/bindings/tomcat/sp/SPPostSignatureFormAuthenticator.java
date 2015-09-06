package org.picketlink.identity.federation.bindings.tomcat.sp;

/**
 * JBID-142: POST form authenticator that can handle signatures at the SP side
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jul 24, 2009
 */
public class SPPostSignatureFormAuthenticator extends SPPostFormAuthenticator {

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
