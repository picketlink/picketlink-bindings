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

import java.net.URI;
import java.security.Principal;

import javax.annotation.PostConstruct;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.web.util.PostBindingUtil;

/**
 * Generates a SAML Assertion for an User
 *
 * @author Anil Saldhana
 * @since June 05, 2014
 */
@Path("/saml")
public class SAMLEndpoint {

    private String subjectConfirmationMethod = JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER.get();

    @Context
    private ServletConfig servletConfig;

    private String issuer = null;

    private PicketLinkCoreSTS sts = null;

    @POST
    public Response generateAssertion(@Context HttpServletRequest httpServletRequest,
            @Context HttpServletResponse httpServletResponse) throws Exception {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null) {
            // Send Error Response
            return Response.status(403).build();
        }
        if (issuer == null) {

        }
        // We have an authenticated user - create a SAML token
        XMLGregorianCalendar issueInstant = XMLTimeUtil.getIssueInstant();

        // Create assertion -> subject
        SubjectType subjectType = new SubjectType();

        // subject -> nameid
        NameIDType nameIDType = new NameIDType();
        nameIDType.setFormat(URI.create(JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get()));
        nameIDType.setValue(principal.getName());

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

        //Check if the STS is null
        setupSTS();

        sts.issueToken(samlProtocolContext);

        AssertionType assertionType = samlProtocolContext.getIssuedAssertion();
        // TODO: sign/encrypt
        String base64EncodedAssertion = PostBindingUtil.base64Encode(AssertionUtil.asString(assertionType));

        return Response.status(200).entity(base64EncodedAssertion).build();
    }

    @PostConstruct
    public void initialize() {
        System.out.println("INITIALIZE");
        if (servletConfig != null) {
            issuer = servletConfig.getInitParameter("issuer");
            if (issuer == null) {
                issuer = "PicketLink_SAML_REST";
            }
        }
        setupSTS();
    }

    protected void setupSTS(){
        if(sts == null){
            sts = PicketLinkCoreSTS.instance();
            sts.installDefaultConfiguration();
        }
    }
}
