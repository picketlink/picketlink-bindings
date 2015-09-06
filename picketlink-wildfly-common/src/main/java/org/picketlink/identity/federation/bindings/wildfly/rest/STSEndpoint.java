package org.picketlink.identity.federation.bindings.wildfly.rest;

import javax.annotation.PostConstruct;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.ws.rs.core.Context;
import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.STSType;
import org.picketlink.identity.federation.bindings.wildfly.providers.OAuth2TokenProvider;
import org.picketlink.identity.federation.bindings.wildfly.providers.OAuthProtocolContext;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.identity.federation.core.wstrust.PicketLinkSTSConfiguration;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;

import java.io.InputStream;
import java.net.URI;

/**
 * JAX-RS Endpoints driven by the STS
 *
 * @author Anil Saldhana
 * @since June 16, 2014
 */
public class STSEndpoint {
    protected String subjectConfirmationMethod = JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER.get();

    protected static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer";

    protected static final String GRANT_TYPE_PARAMETER = "grant_type";

    protected static final String ASSERTION_PARAMETER = "assertion";

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
                try {
                    loadConfiguration();
                } catch (ParsingException e) {
                    throw new RuntimeException(e);
                }
                if (servletContext != null) {
                    servletContext.setAttribute("STS", sts);
                }
            }
        }
    }

    /**
     * Create a {@link org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext} given an user
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
     * Given a base64 encoded assertion string, parse into {@link org.picketlink.identity.federation.saml.v2.assertion.AssertionType}
     * @param base64EncodedAssertion
     * @return
     * @throws ParsingException
     */
    protected AssertionType parseAssertion(String base64EncodedAssertion) throws ParsingException {
        InputStream inputStream = PostBindingUtil.base64DecodeAsStream(base64EncodedAssertion);

        // Load the assertion
        SAMLParser samlParser = new SAMLParser();
        return (AssertionType) samlParser.parse(inputStream);
    }

    /**
     * Given a {@link org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext}, issue a
     * {@link org.picketlink.identity.federation.saml.v2.assertion.AssertionType} using the STS
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
     *
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

    /**
     * Given a SAML Assertion, validate
     * @param samlProtocolContext
     * @return
     */
    public boolean validate(SAMLProtocolContext samlProtocolContext) {
        try {
            checkAndSetUpSTS();
            sts.validateToken(samlProtocolContext);
            return true;
        } catch (ProcessingException pe) {
            return false;
        }
    }

    /**
     * Load the configuration
     * @throws ParsingException
     */
    protected void loadConfiguration() throws ParsingException {
        InputStream inputStream = null;
        if(servletContext != null) {
            inputStream = servletContext.getResourceAsStream(GeneralConstants.CONFIG_FILE_LOCATION);
        }
        if(inputStream == null) {
            inputStream = getClass().getClassLoader().getResourceAsStream("picketlink.xml");
        }
        if(inputStream != null) {
            PicketLinkType picketLinkConfiguration = ConfigurationUtil.getConfiguration(inputStream);
            STSType stsType = picketLinkConfiguration.getStsType();
            if(stsType != null) {
                sts.initialize(new PicketLinkSTSConfiguration(stsType));
            }
        } else {
            sts.installDefaultConfiguration();
            try {
                sts.getConfiguration().addTokenProvider(OAuthProtocolContext.OAUTH_2_0_NS,
                        OAuth2TokenProvider.class.newInstance());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
