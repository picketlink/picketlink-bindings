package org.picketlink.trust.jbossws.handler;

import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.identity.federation.core.util.SOAPUtil;
import org.picketlink.trust.jbossws.Constants;
import org.picketlink.trust.jbossws.Util;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.security.Principal;

/**
 * @author pskopek@redhat.com
 */
@SuppressWarnings({"rawtypes", "restriction"})
public class SamlRequestSecurityTokenHandler extends AbstractPicketLinkTrustHandler {

    private SOAPFactory factory = null;

    @Override
    protected boolean handleInbound(MessageContext msgContext) {

        String username = getUserPrincipalName(msgContext);

        SOAPMessage sm = ((SOAPMessageContext) msgContext).getMessage();
        SOAPEnvelope envelope;
        try {
            envelope = sm.getSOAPPart().getEnvelope();
            SOAPBodyElement rst = (SOAPBodyElement) Util
                .findElement(envelope, new QName(WSTrustConstants.BASE_NAMESPACE, WSTrustConstants.RST));
            if (rst != null) {
                rst.addChildElement(createUsernameToken(username));
            }
        } catch (SOAPException e) {
            logger.jbossWSUnableToCreateBinaryToken(e);
        }
        if (logger.isTraceEnabled()) {
            logger.trace("SOAPMessage(SamlRequestSecurityTokenHandler)=" + SOAPUtil.soapMessageAsString(sm));
        }
        return true;
    }

    /**
     * Given a binary token, create a {@link SOAPElement}
     *
     * @param token
     *
     * @return
     *
     * @throws SOAPException
     */
    private SOAPElement createUsernameToken(String usernamevalue) throws SOAPException {
        if (factory == null) {
            factory = SOAPFactory.newInstance();
        }
        SOAPElement usernametoken = factory.createElement(Constants.WSSE_USERNAME_TOKEN,
            Constants.WSSE_PREFIX, Constants.WSSE_NS);
        SOAPElement username = factory.createElement(Constants.WSSE_USERNAME, Constants.WSSE_PREFIX,
            Constants.WSSE_NS);
        username.addTextNode(usernamevalue);

        usernametoken.addChildElement(username);
        return usernametoken;
    }

    /**
     * Get the {@link HttpServletRequest} from the {@link MessageContext}
     *
     * @param msgContext
     *
     * @return
     */
    private HttpServletRequest getHttpRequest(MessageContext msgContext) {
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        if (request == null) {
            try {
                request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
            } catch (PolicyContextException e) {
                return null;
            }
        }
        return request;
    }

    protected String getUserPrincipalName(MessageContext msgContext) {
        HttpServletRequest servletRequest = getHttpRequest(msgContext);
        if (servletRequest == null) {
            logger.warn("Cannot get HttpRequest, ignoring " + SamlRequestSecurityTokenHandler.class.getName());
            return null;
        }

        Principal principal = servletRequest.getUserPrincipal();
        if (principal == null) {
            logger.warn("Cannot get Principal, ignoring " + SamlRequestSecurityTokenHandler.class.getName());
            return null;
        }

        return principal.getName();
    }
}
