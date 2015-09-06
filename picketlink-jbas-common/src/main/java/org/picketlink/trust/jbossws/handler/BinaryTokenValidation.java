package org.picketlink.trust.jbossws.handler;

import javax.xml.ws.handler.MessageContext;

/**
 * Interface for token validation to be supplied to @MapBasedTokenHandler and @BinaryTokenHandler.
 *
 * @author pskopek
 */
public interface BinaryTokenValidation {

    boolean validateBinaryToken(Object token, MessageContext msgContext);
}
