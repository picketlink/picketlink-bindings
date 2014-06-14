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
package org.picketlink.trust.jbossws.jaas;

import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.util.Base64;
import org.picketlink.identity.federation.core.parsers.saml.SAMLAssertionParser;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.servlet.http.HttpServletRequest;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.Principal;
import java.security.acl.Group;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <p> A login module that consumes a SAML Assertion passed via the password piece of a Basic authentication request. In other
 * words, the SAML Assertion should be passed as the password (with a username of "SAML-BEARER-TOKEN") in a BASIC auth style
 * request. The Authorization HTTP header would look like a normal BASIC auth version (e.g. "Basic
 * U0FNTC1CRUFSRVItVE9LRU46PHNhbWw6QXNz="), but the Base64 Decoded Credentials will look like: </p>
 *
 * <pre>
 * SAML-BEARER-TOKEN:<saml:Assertion ...>...</saml:Assertion>
 * </pre>
 * <p> This class will validate the SAML Assertion and then consume it, making the JAAS principal the same as the SAML subject. JAAS
 * role information is pulled from a multi-value SAML Attribute called "Role". </p>
 *
 * @author eric.wittmann@redhat.com
 */
public class SAMLBearerTokenLoginModule extends AbstractServerLoginModule {

    public static final String AUTHORIZATION = "Authorization";
    public static final String BASIC = "Basic";
    public static final String SAML_BEARER_TOKEN = "SAML-BEARER-TOKEN:";

    /** Configured in standalone.xml in the login module */
    private Set<String> allowedIssuers = new HashSet<String>();

    private Principal identity;
    private Set<String> roles = new HashSet<String>();

    /**
     * Constructor.
     */
    public SAMLBearerTokenLoginModule() {
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#initialize(javax.security.auth.Subject,
     * javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        String val = (String) options.get("allowedIssuers");
        if (val != null) {
            String[] split = val.split(",");
            for (String issuer : split) {
                if (issuer != null && issuer.trim().length() > 0) {
                    allowedIssuers.add(issuer);
                }
            }
        }
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        InputStream is = null;
        try {
            HttpServletRequest request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
            String authorization = request.getHeader(AUTHORIZATION);
            if (authorization != null && authorization.startsWith(BASIC)) {
                String b64Data = authorization.substring(6);
                byte[] dataBytes = Base64.decode(b64Data);
                String data = new String(dataBytes, "UTF-8");
                if (data.startsWith(SAML_BEARER_TOKEN)) {
                    String assertionData = data.substring(18);
                    SAMLAssertionParser parser = new SAMLAssertionParser();
                    is = new ByteArrayInputStream(assertionData.getBytes("UTF-8"));
                    XMLEventReader xmlEventReader = XMLInputFactory.newInstance().createXMLEventReader(is);
                    Object parsed = parser.parse(xmlEventReader);
                    AssertionType assertion = (AssertionType) parsed;
                    validateAssertion(assertion, request);
                    consumeAssertion(assertion);
                    loginOk = true;
                    return true;
                }
            }
        } catch (LoginException le) {
            throw le;
        } catch (Exception e) {
            e.printStackTrace();
            loginOk = false;
            return false;
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                }
            }
        }
        return super.login();
    }

    /**
     * Validates that the assertion is acceptable based on configurable criteria.
     *
     * @param assertion
     * @param request
     *
     * @throws LoginException
     */
    private void validateAssertion(AssertionType assertion, HttpServletRequest request) throws LoginException {
        // Possibly fail the assertion based on issuer.
        String issuer = assertion.getIssuer().getValue();
        if (!allowedIssuers.contains(issuer)) {
            throw new LoginException("Dis-allowed SAML Assertion Issuer: " + issuer + " Allowed: " + allowedIssuers);
        }

        // Possibly fail the assertion based on audience restriction
        String currentAudience = request.getContextPath();
        Set<String> audienceRestrictions = getAudienceRestrictions(assertion);
        if (!audienceRestrictions.contains(currentAudience)) {
            throw new LoginException("SAML Assertion Audience Restrictions not valid for this context (" + currentAudience
                + ")");
        }

        // Possibly fail the assertion based on time.
        try {
            ConditionsType conditionsType = assertion.getConditions();
            if (conditionsType != null) {
                XMLGregorianCalendar now = XMLTimeUtil.getIssueInstant();
                XMLGregorianCalendar notBefore = conditionsType.getNotBefore();
                XMLGregorianCalendar notOnOrAfter = conditionsType.getNotOnOrAfter();
                if (!XMLTimeUtil.isValid(now, notBefore, notOnOrAfter)) {
                    String msg = "SAML Assertion has expired: " + "Now=" + now.toXMLFormat() + " ::notBefore="
                        + notBefore.toXMLFormat() + " ::notOnOrAfter=" + notOnOrAfter;
                    throw new LoginException(msg);
                }
            } else {
                throw new LoginException("SAML Assertion not valid (no Conditions supplied).");
            }
        } catch (ConfigurationException e) {
            // should never happen - see AssertionUtil.hasExpired code for why
            throw new LoginException(e.getMessage());
        }
    }

    /**
     * Gets the audience restriction condition.
     *
     * @param assertion
     */
    private Set<String> getAudienceRestrictions(AssertionType assertion) {
        Set<String> rval = new HashSet<String>();
        if (assertion == null || assertion.getConditions() == null || assertion.getConditions().getConditions() == null) {
            return rval;
        }

        List<ConditionAbstractType> conditions = assertion.getConditions().getConditions();
        for (ConditionAbstractType conditionAbstractType : conditions) {
            if (conditionAbstractType instanceof AudienceRestrictionType) {
                AudienceRestrictionType art = (AudienceRestrictionType) conditionAbstractType;
                List<URI> audiences = art.getAudience();
                for (URI uri : audiences) {
                    rval.add(uri.toString());
                }
            }
        }

        return rval;
    }

    /**
     * Consumes the assertion, resulting in the extraction of the Subject as the JAAS principal and the Role Statements as the JAAS
     * roles.
     *
     * @param assertion
     *
     * @throws Exception
     */
    private void consumeAssertion(AssertionType assertion) throws Exception {
        SubjectType samlSubjectType = assertion.getSubject();
        String samlSubject = ((NameIDType) samlSubjectType.getSubType().getBaseID()).getValue();
        identity = createIdentity(samlSubject);

        Set<StatementAbstractType> statements = assertion.getStatements();
        for (StatementAbstractType statement : statements) {
            if (statement instanceof AttributeStatementType) {
                AttributeStatementType attrStatement = (AttributeStatementType) statement;
                List<ASTChoiceType> attributes = attrStatement.getAttributes();
                for (ASTChoiceType astChoiceType : attributes) {
                    if (astChoiceType.getAttribute() != null && astChoiceType.getAttribute().getName().equals("Role")) {
                        List<Object> values = astChoiceType.getAttribute().getAttributeValue();
                        for (Object roleValue : values) {
                            if (roleValue != null) {
                                roles.add(roleValue.toString());
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getIdentity()
     */
    @Override
    protected Principal getIdentity() {
        return identity;
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getRoleSets()
     */
    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group[] groups = new Group[1];
        groups[0] = new SimpleGroup("Roles");
        try {
            for (String role : roles) {
                groups[0].addMember(createIdentity(role));
            }
        } catch (Exception e) {
            throw new LoginException("Failed to create group principal: " + e.getMessage());
        }
        return groups;
    }
}
