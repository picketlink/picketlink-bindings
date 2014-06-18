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
import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.bindings.wildfly.providers.OAuth2TokenProvider;
import org.picketlink.identity.federation.bindings.wildfly.providers.OAuthProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

import java.net.URI;

/**
 * JAX-RS Endpoints driven by the STS
 *
 * @author Anil Saldhana
 * @since June 16, 2014
 */
public class STSEndpoint {
    private String subjectConfirmationMethod = JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER.get();

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

    /**
     * Create a {@link org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext}
     * given an user
     *
     * @param userName
     * @return
     * @throws ConfigurationException
     */
    protected SAMLProtocolContext getSAMLProtocolContext(String userName) throws ConfigurationException {
        // We have an authenticated user - create a SAML token
        XMLGregorianCalendar issueInstant = XMLTimeUtil.getIssueInstant();

        // Create assertion -> subject
        SubjectType subjectType = new SubjectType();

        // subject -> nameid
        NameIDType nameIDType = new NameIDType();
        nameIDType.setFormat(URI.create(JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get()));
        nameIDType.setValue(userName);

        SubjectType.STSubType subType = new SubjectType.STSubType();
        subType.addBaseID(nameIDType);
        subjectType.setSubType(subType);

        SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
        subjectConfirmation.setMethod(subjectConfirmationMethod);

        SubjectConfirmationDataType subjectConfirmationData = new SubjectConfirmationDataType();
        subjectConfirmationData.setInResponseTo("REST_REQUEST");
        subjectConfirmationData.setNotOnOrAfter(issueInstant);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subjectType.addConfirmation(subjectConfirmation);

        SAMLProtocolContext samlProtocolContext = new SAMLProtocolContext();
        samlProtocolContext.setSubjectType(subjectType);

        NameIDType issuerNameIDType = new NameIDType();
        issuerNameIDType.setValue(issuer);
        samlProtocolContext.setIssuerID(issuerNameIDType);
        return samlProtocolContext;
    }

    /**
     * Given a {@link org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext},
     * issue a {@link org.picketlink.identity.federation.saml.v2.assertion.AssertionType} using the STS
     *
     * @param samlProtocolContext
     * @return
     * @throws ProcessingException
     */
    protected AssertionType issueSAMLAssertion(SAMLProtocolContext samlProtocolContext) throws ProcessingException {
        // Check if the STS is null
        checkAndSetUpSTS();

        sts.issueToken(samlProtocolContext);

        return samlProtocolContext.getIssuedAssertion();
    }

    /**
     * Given an assertion ID, issue an OAuth token using the STS
     * @param assertionID
     * @return
     * @throws ProcessingException
     */
    protected String issueOAuthToken(String assertionID) throws ProcessingException {
        checkAndSetUpSTS();

        // Ask the STS to issue a token
        OAuthProtocolContext oAuthProtocolContext = new OAuthProtocolContext();
        oAuthProtocolContext.setSamlAssertionID(assertionID);
        sts.issueToken(oAuthProtocolContext);

        return oAuthProtocolContext.getToken();
    }
}