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
package org.picketlink.identity.federation.bindings.wildfly.rest;

import javax.annotation.PostConstruct;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.ws.rs.core.Context;

import org.picketlink.identity.federation.bindings.wildfly.providers.OAuth2TokenProvider;
import org.picketlink.identity.federation.bindings.wildfly.providers.OAuthProtocolContext;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;

/**
 * JAX-RS Endpoints driven by the STS
 * @author Anil Saldhana
 * @since June 16, 2014
 */
public class STSEndpoint {
    @Context
    protected ServletContext servletContext;

    @Context
    protected ServletConfig servletConfig;

    protected String issuer = null;

    protected PicketLinkCoreSTS sts = null;

    @PostConstruct
    public void initialize() {
        if (servletConfig != null) {
            issuer = servletConfig.getInitParameter("issuer");
            if (issuer == null) {
                issuer = "PicketLink_SAML_REST";
            }
        }
        checkAndSetUpSTS();
    }

    protected void checkAndSetUpSTS() {
        if (sts == null) {
            if (servletContext != null) {
                sts = (PicketLinkCoreSTS) servletContext.getAttribute("STS");
            }
            if (sts == null) {
                sts = PicketLinkCoreSTS.instance();
                sts.installDefaultConfiguration();
                try {
                    sts.getConfiguration().addTokenProvider(OAuthProtocolContext.OAUTH_2_0_NS,
                            OAuth2TokenProvider.class.newInstance());
                } catch (InstantiationException e) {
                    e.printStackTrace();
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
                if (servletContext != null) {
                    servletContext.setAttribute("STS", sts);
                }
            }
        }
    }
}
