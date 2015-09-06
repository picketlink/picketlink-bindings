package org.picketlink.trust.jbossws.handler;

import org.jboss.security.AuthorizationManager;

import javax.xml.ws.handler.MessageContext;

/**
 * An authorization handler for the POJO Web services Based on the Authorize Operation on the JBossWS Native stack
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author Anil.Saldhana@redhat.com
 * @since Apr 11, 2011
 */
public class WSAuthorizationHandler extends AbstractWSAuthorizationHandler {

    protected AuthorizationManager getAuthorizationManager(MessageContext msgContext) {
        return (AuthorizationManager) lookupJNDI("java:comp/env/security/authorizationMgr");
    }
}
