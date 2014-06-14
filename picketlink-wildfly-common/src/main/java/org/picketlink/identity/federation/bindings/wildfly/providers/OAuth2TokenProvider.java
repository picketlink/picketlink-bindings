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