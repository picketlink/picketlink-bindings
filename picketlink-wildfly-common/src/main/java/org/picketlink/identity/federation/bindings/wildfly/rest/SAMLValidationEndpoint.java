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

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

import org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;

/**
 * REST endpoint to validate SAML Assertions
 * @author Anil Saldhana
 * @since June 17, 2014
 */
@Path("/samlvalidate")
public class SAMLValidationEndpoint extends STSEndpoint {

    /**
     * Validate an already issued assertion
     * @param httpServletRequest
     * @return
     * @throws Exception
     */
    @POST
    public String validate(@Context HttpServletRequest httpServletRequest) throws Exception {
        String base64EncodedAssertion = httpServletRequest.getParameter(ASSERTION_PARAMETER);
        if(base64EncodedAssertion != null) {
            AssertionType samlAssertion = parseAssertion(base64EncodedAssertion);
            SAMLProtocolContext samlProtocolContext = new SAMLProtocolContext();
            samlProtocolContext.setIssuedAssertion(samlAssertion);

            boolean isValid = validate(samlProtocolContext);
            if(isValid){
                return "true";
            }
        }
        return "false";
    }
}
