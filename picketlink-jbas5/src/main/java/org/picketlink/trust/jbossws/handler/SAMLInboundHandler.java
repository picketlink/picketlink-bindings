
package org.picketlink.trust.jbossws.handler;

import javax.xml.ws.handler.MessageContext;

/**
 * <p>{@link SAML2Handler} implementation to handle only inbound messages.</p>
 *
 * @author Pedro Igor
 */
public class SAMLInboundHandler extends SAML2Handler {

    @Override
    protected boolean handleOutbound(MessageContext msgContext) {
        // noop
        return true;
    }
}
