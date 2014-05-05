/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
    public final static String OAUTH_2_0_NS = "urn:oauth:2:0";
    public final static QName QNAME = new QName(OAUTH_2_0_NS);

    private String token;

    private String samlAssertionID;

    @Override
    public String serviceName() {
        throw new UnsupportedOperationException();
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