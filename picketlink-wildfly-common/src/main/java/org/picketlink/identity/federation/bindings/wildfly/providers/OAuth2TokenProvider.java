package org.picketlink.identity.federation.bindings.wildfly.providers;

import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;
import org.picketlink.identity.federation.core.sts.AbstractSecurityTokenProvider;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.util.UUID;

/**
 * Implementation of {@link org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider}
 * for OAuth2
 *
 * @author Anil Saldhana
 * @since April 29, 2014
 */
public class OAuth2TokenProvider extends AbstractSecurityTokenProvider implements SecurityTokenProvider {
    @Override
    public boolean supports(String namespace) {
        return OAuthProtocolContext.OAUTH_2_0_NS.equals(namespace);
    }

    @Override
    public String tokenType() {
        return OAuthProtocolContext.OAUTH_2_0_NS;
    }

    @Override
    public QName getSupportedQName() {
        return new QName(OAuthProtocolContext.OAUTH_2_0_NS);
    }

    @Override
    public String family() {
        return FAMILY_TYPE.OAUTH.name();
    }

    @Override
    public void issueToken(ProtocolContext context) throws ProcessingException {
        if(context instanceof OAuthProtocolContext == false){
            return;
        }

        OAuthProtocolContext oAuthProtocolContext = (OAuthProtocolContext) context;
        String samlAssertionID = oAuthProtocolContext.getSamlAssertionID();
        check();
        String generatedToken = UUID.randomUUID().toString();
        oAuthProtocolContext.setToken(generatedToken);

        //Store in the token registry
        try {
            this.tokenRegistry.addToken(samlAssertionID,generatedToken);
        } catch (IOException e) {
            throw new ProcessingException(e);
        }
    }

    @Override
    public void renewToken(ProtocolContext context) throws ProcessingException {
        if(context instanceof OAuthProtocolContext == false){
            return;
        }
        check();
        //Nothing to do
    }

    @Override
    public void cancelToken(ProtocolContext context) throws ProcessingException {
        if(context instanceof OAuthProtocolContext == false){
            return;
        }
        OAuthProtocolContext oAuthProtocolContext = (OAuthProtocolContext) context;
        String samlAssertionID = oAuthProtocolContext.getSamlAssertionID();
        check();
        try {
            this.tokenRegistry.removeToken(samlAssertionID);
        } catch (IOException e) {
            throw new ProcessingException(e);
        }
    }

    @Override
    public void validateToken(ProtocolContext context) throws ProcessingException {
        if(context instanceof OAuthProtocolContext == false){
            return;
        }

        OAuthProtocolContext oAuthProtocolContext = (OAuthProtocolContext) context;
        String samlAssertionID = oAuthProtocolContext.getSamlAssertionID();
        check();
        String oauthToken = (String) tokenRegistry.getToken(samlAssertionID);
        if(oauthToken == null){
            throw new ProcessingException("Not Valid");
        }
    }

    protected void check() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PicketLinkCoreSTS.rte);
        }
    }
}
