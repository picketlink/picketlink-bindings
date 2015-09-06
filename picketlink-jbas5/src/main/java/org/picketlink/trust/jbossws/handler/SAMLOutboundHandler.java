
package org.picketlink.trust.jbossws.handler;

import javax.xml.ws.handler.MessageContext;

/**
 * <p>{@link SAML2Handler} implementation to handle only outbound messages.</p>
 *
 * @author Pedro Igor
 */
public class SAMLOutboundHandler extends SAML2Handler {

    @Override
    protected boolean handleInbound(MessageContext msgContext) {
        // noop
        return true;
    }
}
