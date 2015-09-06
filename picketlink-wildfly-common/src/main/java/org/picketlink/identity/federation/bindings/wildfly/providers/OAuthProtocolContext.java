package org.picketlink.identity.federation.bindings.wildfly.providers;

import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;

import javax.xml.namespace.QName;

/**
 * Implementation of {@link org.picketlink.identity.federation.core.interfaces.ProtocolContext}
 * for OAuth
 * @author Anil Saldhana
 * @since April 29, 2014
 */
public class OAuthProtocolContext implements ProtocolContext {
    public static final String OAUTH_2_0_NS = "urn:oauth:2:0";
    public static final QName QNAME = new QName(OAUTH_2_0_NS);

    private String token;

    private String samlAssertionID;

    @Override
    public String serviceName() {
        return null;
    }

    @Override
    public String tokenType() {
        return OAUTH_2_0_NS;
    }

    @Override
    public QName getQName() {
        return QNAME ;
    }

    @Override
    public String family() {
        return SecurityTokenProvider.FAMILY_TYPE.OAUTH.name();
    }

    /**
     * Get the OAuth Token
     * @return
     */
    public String getToken() {
        return token;
    }

    /**
     * Set the OAuth Token
     * @param token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Get the SAML Assertion ID that
     * OAuth Token may represent
     * @return
     */
    public String getSamlAssertionID() {
        return samlAssertionID;
    }

    /**
     * Set the SAML Assertion ID that this OAuth Token represents
     * @param samlAssertionID
     */
    public void setSamlAssertionID(String samlAssertionID) {
        this.samlAssertionID = samlAssertionID;
    }
}
