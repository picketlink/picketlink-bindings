package org.picketlink.trust.jbossws.handler;

import org.jboss.security.AuthenticationManager;

import javax.xml.ws.handler.MessageContext;

/**
 * Perform Authentication for POJO Web Services
 *
 * Based on the Authorize Operation on the JBossWS Native stack
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author Anil.Saldhana@redhat.com
 * @since Apr 11, 2011
 */
public class WSAuthenticationHandler extends AbstractWSAuthenticationHandler {

    @Override
    protected AuthenticationManager getAuthenticationManager(MessageContext msgContext) {
        return (AuthenticationManager) lookupJNDI("java:comp/env/security/securityMgr");
    }
}
