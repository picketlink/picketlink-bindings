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
package org.picketlink.social.openid.providers;

import org.jboss.security.xacml.sunxacml.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;
import org.picketlink.identity.federation.core.sts.AbstractSecurityTokenProvider;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.social.standalone.openid.providers.helpers.OpenIDParameterList;
import org.picketlink.social.standalone.openid.providers.helpers.OpenIDProtocolContext;
import org.picketlink.social.standalone.openid.providers.helpers.OpenIDProviderManager;
import org.picketlink.social.standalone.openid.providers.helpers.OpenIDTokenRegistryStore;

import javax.xml.namespace.QName;

/**
 * An OpenID Token Provider for the PicketLink STS
 * @author Anil.Saldhana@redhat.com
 * @since Jan 20, 2011
 */
public class OpenIDTokenProvider extends AbstractSecurityTokenProvider implements SecurityTokenProvider {

    public static final String OPENID_1_0_NS = "urn:openid:1:0";
    public static final String OPENID_1_1_NS = "urn:openid:1:1";
    public static final String OPENID_2_0_NS = "urn:openid:2:0";

    protected static OpenIDProviderManager serverManager = null;

    static {
        if (serverManager == null) {
            serverManager = new OpenIDProviderManager();
            serverManager.initialize(new OpenIDTokenRegistryStore(), new OpenIDTokenRegistryStore());
        }
    };

    /**
     * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#supports(String)
     */
    public boolean supports(String namespace) {
        return OPENID_1_0_NS.equals(namespace);
    }

    /**
     * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#tokenType()
     */
    public String tokenType() {
        return OPENID_1_0_NS;
    }

    /**
     * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#getSupportedQName()
     */
    public QName getSupportedQName() {
        return new QName(OPENID_1_0_NS);
    }

    /**
     * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#family()
     */
    public String family() {
        return SecurityTokenProvider.FAMILY_TYPE.OPENID.name();
    }

    /**
     * @param context
     *
     * @throws ProcessingException
     */
    public void issueToken(ProtocolContext context) throws ProcessingException {
        if (context instanceof OpenIDProtocolContext == false) {
            return;
        }

        check();

        OpenIDProtocolContext openIDProtoCtx = (OpenIDProtocolContext) context;
        if (serverManager.getEndPoint() == null) {
            serverManager.setEndPoint(openIDProtoCtx.getEndpoint());
        }

        OpenIDParameterList requestp = openIDProtoCtx.getRequestParameterList();
        OpenIDProviderManager.OpenIDMessage responsem = null;

        if (openIDProtoCtx.getIssueError()) {
            String errorText = openIDProtoCtx.getErrorText() == null ? "Unknown request" : openIDProtoCtx.getErrorText();

            responsem = serverManager.getDirectError(errorText);
        } else {
            OpenIDProtocolContext.MODE mode = openIDProtoCtx.getMode();
            switch (mode) {
                case ASSOCIATE:
                    responsem = serverManager.processAssociationRequest(requestp);
                    break;

                case CHECK_AUTHENTICATION:
                    validateToken(openIDProtoCtx);
                    return;

                case CHECK_ID_SETUP:
                case CHECK_ID_IMMEDIATE:
                    OpenIDProtocolContext.AUTH_HOLDER authHolder = openIDProtoCtx.getAuthenticationHolder();
                    if (authHolder == null) {
                        throw new ProcessingException("Authentication Holder is null");
                    }

                    responsem = serverManager.processAuthenticationRequest(requestp, authHolder.getUserSelectedId(),
                        authHolder.getUserSelectedClaimedId(), authHolder.isAuthenticatedAndApproved());
                    break;
                default:
                    throw new ProcessingException("Unknown mode");
            }
        }
        openIDProtoCtx.setResponseMessage(responsem);
    }

    public void renewToken(ProtocolContext context) throws ProcessingException {
        if (context instanceof OpenIDProtocolContext == false) {
            return;
        }

        check();
    }

    public void cancelToken(ProtocolContext context) throws ProcessingException {
        if (context instanceof OpenIDProtocolContext == false) {
            return;
        }

        check();
    }

    public void validateToken(ProtocolContext context) throws ProcessingException {
        if (context instanceof OpenIDProtocolContext == false) {
            return;
        }

        check();

        OpenIDProtocolContext openIDProtoCtx = (OpenIDProtocolContext) context;
        if (serverManager.getEndPoint() == null) {
            serverManager.setEndPoint(openIDProtoCtx.getEndpoint());
        }

        OpenIDParameterList requestp = openIDProtoCtx.getRequestParameterList();
        OpenIDProviderManager.OpenIDMessage responsem = serverManager.verify(requestp);
        openIDProtoCtx.setResponseMessage(responsem);
    }

    protected void check() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PicketLinkCoreSTS.rte);
        }
    }
}