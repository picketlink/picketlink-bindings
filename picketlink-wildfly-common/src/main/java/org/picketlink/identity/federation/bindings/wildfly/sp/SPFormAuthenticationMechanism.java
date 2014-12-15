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
package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.handlers.security.ServletFormAuthenticationMechanism;
import org.jboss.security.audit.AuditLevel;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.exceptions.fed.AssertionExpiredException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StringUtil;
import org.picketlink.common.util.SystemPropertiesUtil;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.handler.Handlers;
import org.picketlink.identity.federation.api.saml.v2.metadata.MetaDataExtractor;
import org.picketlink.identity.federation.bindings.wildfly.ServiceProviderSAMLContext;
import org.picketlink.identity.federation.core.SerializablePrincipal;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditEvent;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditEventType;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.factories.SAML2HandlerChainFactory;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChain;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.HandlerUtil;
import org.picketlink.identity.federation.core.saml.workflow.ServiceProviderSAMLWorkflow;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AssertionType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AuthenticationStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11StatementAbstractType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType;
import org.picketlink.identity.federation.saml.v1.protocol.SAML11ResponseType;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntitiesDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.web.config.AbstractSAMLConfigurationProvider;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.core.SessionManager;
import org.picketlink.identity.federation.web.process.ServiceProviderBaseProcessor;
import org.picketlink.identity.federation.web.process.ServiceProviderSAMLRequestProcessor;
import org.picketlink.identity.federation.web.process.ServiceProviderSAMLResponseProcessor;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wildfly.extension.undertow.security.AccountImpl;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionListener;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.picketlink.common.constants.GeneralConstants.CONFIG_FILE_LOCATION;
import static org.picketlink.common.util.StringUtil.isNotNull;
import static org.picketlink.common.util.StringUtil.isNullOrEmpty;

/**
 * PicketLink SP Authentication Mechanism that falls back to FORM
 *
 * @author Anil Saldhana
 * @since November 04, 2013
 */
@WebListener
public class SPFormAuthenticationMechanism extends ServletFormAuthenticationMechanism {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    public static final String INITIAL_LOCATION_STORED = "org.picketlink.federation.saml.initial_location";

    protected transient String samlHandlerChainClass = null;

    protected final ServletContext servletContext;

    protected Map<String, Object> chainConfigOptions = new HashMap<String, Object>();
    /**
     * The user can inject a fully qualified name of a {@link org.picketlink.identity.federation.web.util.SAMLConfigurationProvider}
     */
    protected SAMLConfigurationProvider configProvider;
    /**
     * If the service provider is configured with an IDP metadata file, then this certificate can be picked up from the metadata
     */
    protected transient X509Certificate idpCertificate = null;
    protected int timerInterval = -1;

    protected Timer timer = null;

    public static final String EMPTY_PASSWORD = "EMPTY_STR";

    protected boolean enableAudit = false;

    public static final String FORM_ACCOUNT_NOTE = "picketlink.form.account";
    public static final String FORM_REQUEST_NOTE = "picketlink.REQUEST";

    protected transient SAML2HandlerChain chain = null;

    protected SPType spConfiguration = null;

    protected PicketLinkType picketLinkConfiguration = null;

    protected String serviceURL = null;

    protected String identityURL = null;

    protected String issuerID = null;

    protected String configFile;

    // Whether the authenticator has to to save and restore request
    protected boolean saveRestoreRequest = true;

    /**
     * A Lock for Handler operations in the chain
     */
    protected Lock chainLock = new ReentrantLock();

    protected String canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;

    protected PicketLinkAuditHelper auditHelper;
    protected TrustKeyManager keyManager;
    private IDPSSODescriptorType idpMetadata;

    public SPFormAuthenticationMechanism(FormParserFactory parserFactory, String name, String loginPage, String errorPage, ServletContext servletContext, SAMLConfigurationProvider configProvider, PicketLinkAuditHelper auditHelper) {
        super(parserFactory, name, loginPage, errorPage);
        this.servletContext = servletContext;
        this.configProvider = configProvider;
        this.auditHelper = auditHelper;
        startPicketLink();
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        if (exchange.isResponseComplete()) {
            return new ChallengeResult(true);
        }

        return new ChallengeResult(true, HttpServletResponse.SC_FOUND);
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        // TODO: Deal with character encoding
        // request.setCharacterEncoding(xyz)

        // Get the session

        final ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        ServletContext servletContext = servletRequestContext.getCurrentServletContext();
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

        HttpSession session = request.getSession(true);

        // check if this call is resulting from the redirect after successful authentication.
        // if so, make the authentication successful and continue the original request
        //if (saveRestoreRequest && matchRequest(request)) {
        if (saveRestoreRequest) {
            Account savedAccount = (Account) session.getAttribute(FORM_ACCOUNT_NOTE);
            if(savedAccount != null){
                register(securityContext, savedAccount);
            }
        }
        ServiceProviderSAMLWorkflow serviceProviderSAMLWorkflow = new ServiceProviderSAMLWorkflow();

        // Eagerly look for Local LogOut
        boolean localLogout = serviceProviderSAMLWorkflow.isLocalLogoutRequest(request);

        if (localLogout) {
            try {
                serviceProviderSAMLWorkflow.sendToLogoutPage(request, response, session, servletContext, this.spConfiguration.getLogOutPage());
            } catch (ServletException e) {
                logger.samlLogoutError(e);
                throw new RuntimeException(e);
            } catch (IOException e1) {
                logger.samlLogoutError(e1);
                throw new RuntimeException(e1);
            }
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

        Principal principal = request.getUserPrincipal();

        try {
        // If we have already authenticated the user and there is no request from IDP or logout from user
            if (principal != null
                    && !(serviceProviderSAMLWorkflow.isLocalLogoutRequest(request) || isGlobalLogout(request) || isNotNull(samlRequest) || isNotNull(samlResponse)))
                return AuthenticationMechanismOutcome.AUTHENTICATED;

        // General User Request
        if (!isNotNull(samlRequest) && !isNotNull(samlResponse)) {
            session.setAttribute(INITIAL_LOCATION_STORED, true);
            storeInitialLocation(exchange);
            return generalUserRequest(exchange,securityContext);
        }

            // Handle a SAML Response from IDP
            if (isNotNull(samlResponse)) {
                return handleSAMLResponse(exchange, securityContext);
            }

            // Handle SAML Requests from IDP
            if (isNotNull(samlRequest)) {
                return handleSAMLRequest(exchange,securityContext);
            }// end if

            // local authentication
            return super.authenticate(exchange, securityContext);
        } catch (IOException e) {
            if (StringUtil.isNotNull(spConfiguration.getErrorPage())) {
                try {
                    request.getRequestDispatcher(spConfiguration.getErrorPage()).forward(request, response);
                } catch (ServletException e1) {
                    logger.samlErrorPageForwardError(spConfiguration.getErrorPage(), e1);
                }catch (IOException e1) {
                    logger.samlErrorPageForwardError(spConfiguration.getErrorPage(), e1);
                }
                return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
            } else {
                throw new RuntimeException(e);
            }
        }

    }

    private AuthenticationMechanismOutcome handleSAMLResponse(HttpServerExchange exchange, SecurityContext securityContext) throws IOException {
        ServletRequestContext request = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest httpServletRequest = (HttpServletRequest) request.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) request.getServletResponse();

        String samlVersion = getSAMLVersion(httpServletRequest);

        if (!JBossSAMLConstants.VERSION_2_0.get().equals(samlVersion)) {
            return handleSAML11UnsolicitedResponse(httpServletRequest, response, securityContext);
        }

        return handleSAML2Response(exchange, securityContext);
    }

    /**
     * Handle the user invocation for the first time
     *
     * @param httpServerExchange
     * @param securityContext
     * @return
     * @throws IOException
     */
    private AuthenticationMechanismOutcome generalUserRequest(HttpServerExchange httpServerExchange, SecurityContext securityContext) throws IOException{
        ServiceProviderSAMLWorkflow serviceProviderSAMLWorkflow = new ServiceProviderSAMLWorkflow();
        serviceProviderSAMLWorkflow.setRedirectionHandler(new UndertowRedirectionHandler(httpServerExchange));

        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        ServletContext servletContext = servletRequestContext.getCurrentServletContext();
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

        HttpSession session = request.getSession(true);
        boolean willSendRequest = false;

        HTTPContext httpContext = new HTTPContext(request, response, servletContext);
        Set<SAML2Handler> handlers = chain.handlers();

        boolean postBinding = spConfiguration.getBindingType().equals("POST");

        // Neither saml request nor response from IDP
        // So this is a user request
        SAML2HandlerResponse saml2HandlerResponse = null;
        try {
            ServiceProviderBaseProcessor baseProcessor = new ServiceProviderBaseProcessor(postBinding, serviceURL,
                    this.picketLinkConfiguration, this.idpMetadata);
            if (issuerID != null)
                baseProcessor.setIssuer(issuerID);

            baseProcessor.setIdentityURL(identityURL);
            baseProcessor.setAuditHelper(auditHelper);

            saml2HandlerResponse = baseProcessor.process(httpContext, handlers, chainLock);
        } catch (ProcessingException pe) {
            logger.samlSPHandleRequestError(pe);
            throw new RuntimeException(pe);
        } catch (ParsingException pe) {
            logger.samlSPHandleRequestError(pe);
            throw new RuntimeException(pe);
        } catch (ConfigurationException pe) {
            logger.samlSPHandleRequestError(pe);
            throw new RuntimeException(pe);
        }

        willSendRequest = saml2HandlerResponse.getSendRequest();

        Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
        String relayState = saml2HandlerResponse.getRelayState();

        String destination = saml2HandlerResponse.getDestination();
        String destinationQueryStringWithSignature = saml2HandlerResponse.getDestinationQueryStringWithSignature();

        if (destination != null && samlResponseDocument != null) {
            try {
                if (saveRestoreRequest) {
                    storeInitialLocation(httpServerExchange);
                }
                if (enableAudit) {
                    PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                    auditEvent.setType(PicketLinkAuditEventType.REQUEST_TO_IDP);
                    auditEvent.setWhoIsAuditing(servletContext.getContextPath());
                    auditHelper.audit(auditEvent);
                }
                serviceProviderSAMLWorkflow.sendRequestToIDP(destination, samlResponseDocument, relayState, response, willSendRequest,
                        destinationQueryStringWithSignature, isHttpPostBinding());
                return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
            } catch (Exception e) {
                logger.samlSPHandleRequestError(e);
                throw logger.samlSPProcessingExceptionError(e);
            }
        }

        return localAuthentication(httpServerExchange, securityContext);
    }

    protected boolean matchRequest(HttpServletRequest request) {
        return false; // assume this is a fresh request
    }

    protected void register(final SecurityContext securityContext, Account account) {
        securityContext.authenticationComplete(account, "FORM", false);
    }

    /**
     * Fall back on local authentication at the service provider side
     *
     * @param httpServerExchange
     * @param securityContext
     * @return
     * @throws IOException
     */
    protected AuthenticationMechanismOutcome localAuthentication(HttpServerExchange httpServerExchange, SecurityContext securityContext) throws IOException {

        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        ServletContext servletContext = servletRequestContext.getCurrentServletContext();
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

        if (request.getUserPrincipal() == null) {
            logger.samlSPFallingBackToLocalFormAuthentication();// fallback
            try {
                return super.authenticate(httpServerExchange,securityContext);
            } catch (NoSuchMethodError e) {
                /*// Use Reflection
                try {
                    Method method = super.getClass().getMethod("authenticate",
                            new Class[] { HttpServletRequest.class, HttpServletResponse.class, LoginConfig.class });
                    return (Boolean) method.invoke(this, new Object[] { request.getRequest(), response.getResponse(),
                            loginConfig });
                } catch (Exception ex) {
                    throw logger.unableLocalAuthentication(ex);
                }*/
            }
        } else{
            return  AuthenticationMechanismOutcome.AUTHENTICATED;
        }
        return  AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
    }

    /**
     * Handle the IDP Request
     *
     * @param httpServerExchange
     * @param securityContext
     * @return
     * @throws IOException
     */
    private AuthenticationMechanismOutcome handleSAMLRequest(HttpServerExchange httpServerExchange, SecurityContext securityContext) throws IOException {
        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        ServletContext servletContext = servletRequestContext.getCurrentServletContext();
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

        String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
        HTTPContext httpContext = new HTTPContext(request, response, servletContext);
        Set<SAML2Handler> handlers = chain.handlers();

        try {
            ServiceProviderSAMLRequestProcessor requestProcessor = new ServiceProviderSAMLRequestProcessor(
                    request.getMethod().equals("POST"), this.serviceURL, this.picketLinkConfiguration, this.idpMetadata);
            requestProcessor.setTrustKeyManager(keyManager);
            boolean result = requestProcessor.process(samlRequest, httpContext, handlers, chainLock);

            if (enableAudit) {
                PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                auditEvent.setType(PicketLinkAuditEventType.REQUEST_FROM_IDP);
                auditEvent.setWhoIsAuditing(servletContext.getContextPath());
                auditHelper.audit(auditEvent);
            }

            // If response is already commited, we need to stop with processing of HTTP request
            if (response.isCommitted())
                return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;

            if (result)
                return AuthenticationMechanismOutcome.AUTHENTICATED;
        } catch (Exception e) {
            logger.samlSPHandleRequestError(e);
            throw logger.samlSPProcessingExceptionError(e);
        }

        return localAuthentication(httpServerExchange,securityContext);
    }

    /**
     * Handle IDP Response
     *
     * @param httpServerExchange
     * @param securityContext
     * @return
     * @throws IOException
     */
    private AuthenticationMechanismOutcome handleSAML2Response(HttpServerExchange httpServerExchange, SecurityContext securityContext) throws IOException {
        ServiceProviderSAMLWorkflow serviceProviderSAMLWorkflow = new ServiceProviderSAMLWorkflow();

        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        ServletContext servletContext = servletRequestContext.getCurrentServletContext();
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();

        HttpSession session = request.getSession(true);
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

        boolean willSendRequest = false;
        HTTPContext httpContext = new HTTPContext(request, response, servletContext);
        Set<SAML2Handler> handlers = chain.handlers();

        Principal principal = request.getUserPrincipal();

        if (! serviceProviderSAMLWorkflow.validate(request)) {
            throw new IOException(ErrorCodes.VALIDATION_CHECK_FAILED);
        }

        // deal with SAML response from IDP
        try {
            ServiceProviderSAMLResponseProcessor responseProcessor = new ServiceProviderSAMLResponseProcessor(request.getMethod().equals("POST"), serviceURL, this.picketLinkConfiguration, this.idpMetadata);
            if(auditHelper !=  null){
                responseProcessor.setAuditHelper(auditHelper);
            }

            responseProcessor.setTrustKeyManager(keyManager);

            SAML2HandlerResponse saml2HandlerResponse = responseProcessor.process(samlResponse, httpContext, handlers,
                    chainLock);

            Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
            String relayState = saml2HandlerResponse.getRelayState();

            String destination = saml2HandlerResponse.getDestination();

            willSendRequest = saml2HandlerResponse.getSendRequest();

            String destinationQueryStringWithSignature = saml2HandlerResponse.getDestinationQueryStringWithSignature();

            if (destination != null && samlResponseDocument != null) {
                serviceProviderSAMLWorkflow.sendRequestToIDP(destination, samlResponseDocument,
                        relayState, response,
                        willSendRequest, destinationQueryStringWithSignature,
                        spConfiguration.getBindingType().equalsIgnoreCase("POST"));
            } else {
                // See if the session has been invalidated
                boolean sessionValidity = sessionIsValid(session);

                if (!sessionValidity) {
                    serviceProviderSAMLWorkflow.sendToLogoutPage(request, response, session, servletContext, this.spConfiguration.getLogOutPage());
                    return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
                }

                // We got a response with the principal
                final List<String> roles = saml2HandlerResponse.getRoles();
                if (principal == null)
                    principal = (Principal) session.getAttribute(GeneralConstants.PRINCIPAL_ID);

                String username = principal.getName();
                String password = EMPTY_PASSWORD;

                if (logger.isTraceEnabled()) {
                    logger.trace("Roles determined for username=" + username + "=" + Arrays.toString(roles.toArray()));
                }

                ServiceProviderSAMLContext.push(username, roles);

                //TODO: figure out getting the principal via authentication
                IdentityManager identityManager = securityContext.getIdentityManager();

                final Principal userPrincipal = principal;

                Account account = new AccountImpl(userPrincipal, new HashSet<String>(roles), password);

                account = identityManager.verify(account);

                //Register the principal with the request
                register(securityContext, account);

                if (enableAudit) {
                    PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                    auditEvent.setType(PicketLinkAuditEventType.RESPONSE_FROM_IDP);
                    auditEvent.setSubjectName(username);
                    auditEvent.setWhoIsAuditing(servletContext.getContextPath());
                    auditHelper.audit(auditEvent);
                }

                // Redirect the user to the originally requested URL
                if (saveRestoreRequest) {
                    // Store the authenticated principal in the session.
                    session.setAttribute(FORM_ACCOUNT_NOTE, account);

                    if (session.getAttribute(INITIAL_LOCATION_STORED) != null) {
                        // Redirect to the original URL.  Note that this will trigger the
                        // authenticator again, but on resubmission we will look in the
                        // session notes to retrieve the authenticated principal and
                        // prevent reauthentication
                        handleRedirectBack(httpServerExchange);
                        httpServerExchange.endExchange();
                    }
                }
                return AuthenticationMechanismOutcome.AUTHENTICATED;
            }
        } catch (ProcessingException pe) {
            Throwable t = pe.getCause();
            if (t != null && t instanceof AssertionExpiredException) {
                logger.error("Assertion has expired. Asking IDP for reissue");
                if (enableAudit) {
                    PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                    auditEvent.setType(PicketLinkAuditEventType.EXPIRED_ASSERTION);
                    auditEvent.setAssertionID(((AssertionExpiredException) t).getId());
                    auditHelper.audit(auditEvent);
                }
                // Just issue a fresh request back to IDP
                return generalUserRequest(httpServerExchange,securityContext);
            }
            logger.samlSPHandleRequestError(pe);
            throw logger.samlSPProcessingExceptionError(pe);
        } catch (Exception e) {
            logger.samlSPHandleRequestError(e);
            throw logger.samlSPProcessingExceptionError(e);
        } finally {
            ServiceProviderSAMLContext.clear();
        }

        return localAuthentication(httpServerExchange,securityContext);
    }
    /**
     * <p>
     * Indicates if the SP is configure with HTTP POST Binding.
     * </p>
     *
     * @return
     */
    protected boolean isHttpPostBinding() {
        return spConfiguration.getBindingType().equalsIgnoreCase("POST");
    }

    protected boolean sessionIsValid(HttpSession session){
        try{
            long sessionTime = session.getCreationTime();
        } catch(IllegalStateException ise){
            return false;
        }
        return true;
    }

    protected String savedRequestURL(HttpSession session){
        StringBuilder builder = new StringBuilder();
        HttpServletRequest request = (HttpServletRequest) session.getAttribute(FORM_REQUEST_NOTE);
        if(request != null){
            builder.append(request.getRequestURI());
            if(request.getQueryString() != null){
                builder.append("?").append(request.getQueryString());
            }
        }
        return builder.toString();
    }

    protected void startPicketLink() {
        SystemPropertiesUtil.ensure();
        Handlers handlers = null;

        //Introduce a timer to reload configuration if desired
        if(timerInterval > 0 ){
            if(timer == null){
                timer = new Timer();
            }
            timer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    processConfiguration();
                    initKeyProvider(servletContext);
                }
            }, timerInterval, timerInterval);
        }

        // Get the chain from config
        if (StringUtil.isNullOrEmpty(samlHandlerChainClass)) {
            chain = SAML2HandlerChainFactory.createChain();
        } else {
            try {
                chain = SAML2HandlerChainFactory.createChain(this.samlHandlerChainClass);
            } catch (ProcessingException e1) {
                throw new RuntimeException(e1);
            }
        }

        this.processConfiguration();

        try {
            if (picketLinkConfiguration != null) {
                handlers = picketLinkConfiguration.getHandlers();
            } else {
                // Get the handlers
                String handlerConfigFileName = GeneralConstants.HANDLER_CONFIG_FILE_LOCATION;
                handlers = ConfigurationUtil.getHandlers(servletContext.getResourceAsStream(handlerConfigFileName));
            }

            chain.addAll(HandlerUtil.getHandlers(handlers));

            this.initKeyProvider(servletContext);
            this.populateChainConfig();
            this.initializeHandlerChain();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        if (this.picketLinkConfiguration == null) {
            this.picketLinkConfiguration = new PicketLinkType();

            this.picketLinkConfiguration.setIdpOrSP(spConfiguration);
            this.picketLinkConfiguration.setHandlers(handlers);
        }

        new SessionManager(servletContext, new SessionManager.InitializationCallback() {
            @Override
            public void registerSessionListener(Class<? extends HttpSessionListener> listener) {
                servletContext.addListener(listener);
            }
        });
    }

    /**
     * <p>
     * Initialize the KeyProvider configurations. This configurations are to be used during signing and validation of SAML
     * assertions.
     * </p>
     *
     * @param context
     */
    protected void initKeyProvider(ServletContext context){
        if (!doSupportSignature()) {
            return;
        }

        KeyProviderType keyProvider = this.spConfiguration.getKeyProvider();

        if (keyProvider == null && doSupportSignature())
            throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyProvider is null for context=" + context.getContextPath());

        try {
            String keyManagerClassName = keyProvider.getClassName();
            if (keyManagerClassName == null)
                throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyManager class name");

            Class<?> clazz = SecurityActions.loadClass(getClass(), keyManagerClassName);

            if (clazz == null)
                throw new ClassNotFoundException(ErrorCodes.CLASS_NOT_LOADED + keyManagerClassName);
            this.keyManager = (TrustKeyManager) clazz.newInstance();

            List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);

            keyManager.setAuthProperties(authProperties);
            keyManager.setValidatingAlias(keyProvider.getValidatingAlias());

            String identityURL = this.spConfiguration.getIdentityURL();

            //Special case when you need X509Data in SignedInfo
            if(authProperties != null){
                for(AuthPropertyType authPropertyType: authProperties){
                    String key = authPropertyType.getKey();
                    if(GeneralConstants.X509CERTIFICATE.equals(key)){
                        //we need X509Certificate in SignedInfo. The value is the alias name
                        keyManager.addAdditionalOption(GeneralConstants.X509CERTIFICATE, authPropertyType.getValue());
                        break;
                    }
                }
            }
            keyManager.addAdditionalOption(ServiceProviderBaseProcessor.IDP_KEY, new URL(identityURL).getHost());
        } catch (Exception e) {
            logger.trustKeyManagerCreationError(e);
            throw new RuntimeException(e.getLocalizedMessage());
        }

        logger.trace("Key Provider=" + keyProvider.getClassName());
    }
    /**
     * <p>
     * Indicates if digital signatures/validation of SAML assertions are enabled. Subclasses that supports signature should
     * override this method.
     * </p>
     *
     * @return
     */
    protected boolean doSupportSignature() {
        if (spConfiguration != null) {
            return spConfiguration.isSupportsSignature();
        }
        return false;
    }
    protected void processConfiguration() {
        InputStream is = null;

        if (isNullOrEmpty(this.configFile)) {
            this.configFile = CONFIG_FILE_LOCATION;
            is = servletContext.getResourceAsStream(this.configFile);
        } else {
            try {
                is = new FileInputStream(this.configFile);
            } catch (FileNotFoundException e) {
                throw logger.samlIDPConfigurationError(e);
            }
        }

        try {
            // Work on the IDP Configuration
            if (configProvider != null) {
                try {
                    if (is == null) {
                        // Try the older version
                        is = servletContext.getResourceAsStream(GeneralConstants.DEPRECATED_CONFIG_FILE_LOCATION);

                        // Additionally parse the deprecated config file
                        if (is != null && configProvider instanceof AbstractSAMLConfigurationProvider) {
                            ((AbstractSAMLConfigurationProvider) configProvider).setConfigFile(is);
                        }
                    } else {
                        // Additionally parse the consolidated config file
                        if (is != null && configProvider instanceof AbstractSAMLConfigurationProvider) {
                            ((AbstractSAMLConfigurationProvider) configProvider).setConsolidatedConfigFile(is);
                        }
                    }

                    picketLinkConfiguration = configProvider.getPicketLinkConfiguration();
                    spConfiguration = configProvider.getSPConfiguration();
                } catch (ProcessingException e) {
                    throw logger.samlSPConfigurationError(e);
                } catch (ParsingException e) {
                    throw logger.samlSPConfigurationError(e);
                }
            } else {
                if (is != null) {
                    try {
                        picketLinkConfiguration = ConfigurationUtil.getConfiguration(is);
                        spConfiguration = (SPType) picketLinkConfiguration.getIdpOrSP();
                    } catch (ParsingException e) {
                        logger.trace(e);
                        throw logger.samlSPConfigurationError(e);
                    }
                } else {
                    is = servletContext.getResourceAsStream(GeneralConstants.DEPRECATED_CONFIG_FILE_LOCATION);
                    if (is == null)
                        throw logger.configurationFileMissing(configFile);
                    spConfiguration = ConfigurationUtil.getSPConfiguration(is);
                }
            }

            //Close the InputStream as we no longer need it
            if(is != null){
                try {
                    is.close();
                } catch (IOException e) {
                    //ignore
                }
            }

            if (this.picketLinkConfiguration != null) {
                enableAudit = picketLinkConfiguration.isEnableAudit();

                //See if we have the system property enabled
                if(!enableAudit){
                    String sysProp = SecurityActions.getSystemProperty(GeneralConstants.AUDIT_ENABLE, "NULL");
                    if(!"NULL".equals(sysProp)){
                        enableAudit = Boolean.parseBoolean(sysProp);
                    }
                }

                if (enableAudit) {
                    if (auditHelper == null) {
                        String securityDomainName = PicketLinkAuditHelper.getSecurityDomainName(servletContext);

                        auditHelper = new PicketLinkAuditHelper(securityDomainName);
                    }
                }
            }

            processIdPMetadata(spConfiguration);

            this.identityURL = spConfiguration.getIdentityURL();
            this.serviceURL = spConfiguration.getServiceURL();
            this.canonicalizationMethod = spConfiguration.getCanonicalizationMethod();

            logger.samlSPSettingCanonicalizationMethod(canonicalizationMethod);
            XMLSignatureUtil.setCanonicalizationMethodType(canonicalizationMethod);

            logger.trace("Identity Provider URL=" + this.identityURL);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void processIdPMetadata(SPType spConfiguration) {
        IDPSSODescriptorType idpssoDescriptorType = null;

        if (isNotNull(spConfiguration.getIdpMetadataFile())) {
            idpssoDescriptorType = getIdpMetadataFromFile(spConfiguration);
        } else {
            idpssoDescriptorType = getIdpMetadataFromProvider(spConfiguration);
        }

        if (idpssoDescriptorType != null) {
            List<EndpointType> endpoints = idpssoDescriptorType.getSingleSignOnService();
            for (EndpointType endpoint : endpoints) {
                String endpointBinding = endpoint.getBinding().toString();
                if (endpointBinding.contains("HTTP-POST")) {
                    endpointBinding = "POST";
                } else if (endpointBinding.contains("HTTP-Redirect")) {
                    endpointBinding = "REDIRECT";
                }
                if (spConfiguration.getBindingType().equals(endpointBinding)) {
                    spConfiguration.setIdentityURL(endpoint.getLocation().toString());
                    break;
                }
            }
            List<KeyDescriptorType> keyDescriptors = idpssoDescriptorType.getKeyDescriptor();
            if (keyDescriptors.size() > 0) {
                this.idpCertificate = MetaDataExtractor.getCertificate(keyDescriptors.get(0));
            }

            this.idpMetadata = idpssoDescriptorType;
        }
    }

    private IDPSSODescriptorType getIdpMetadataFromProvider(SPType spConfiguration) {
        List<EntityDescriptorType> entityDescriptors = CoreConfigUtil.getMetadataConfiguration(spConfiguration,
            this.servletContext);

        if (entityDescriptors != null) {
            for (EntityDescriptorType entityDescriptorType : entityDescriptors) {
                IDPSSODescriptorType idpssoDescriptorType = handleMetadata(entityDescriptorType);

                if (idpssoDescriptorType != null) {
                    return idpssoDescriptorType;
                }
            }
        }

        return null;
    }

    protected IDPSSODescriptorType getIdpMetadataFromFile(SPType configuration) {
        ServletContext servletContext = this.servletContext;
        InputStream is = servletContext.getResourceAsStream(configuration.getIdpMetadataFile());
        if (is == null) {
            return null;
        }

        Object metadata = null;
        try {
            Document samlDocument = DocumentUtil.getDocument(is);
            SAMLParser parser = new SAMLParser();
            metadata = parser.parse(DocumentUtil.getNodeAsStream(samlDocument));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        IDPSSODescriptorType idpSSO = null;
        if (metadata instanceof EntitiesDescriptorType) {
            EntitiesDescriptorType entities = (EntitiesDescriptorType) metadata;
            idpSSO = handleMetadata(entities);
        } else {
            idpSSO = handleMetadata((EntityDescriptorType) metadata);
        }
        if (idpSSO == null) {
            logger.samlSPUnableToGetIDPDescriptorFromMetadata();
            return idpSSO;
        }

        return idpSSO;
    }

    protected IDPSSODescriptorType handleMetadata(EntitiesDescriptorType entities) {
        IDPSSODescriptorType idpSSO = null;

        List<Object> entityDescs = entities.getEntityDescriptor();
        for (Object entityDescriptor : entityDescs) {
            if (entityDescriptor instanceof EntitiesDescriptorType) {
                idpSSO = getIDPSSODescriptor(entities);
            } else {
                idpSSO = handleMetadata((EntityDescriptorType) entityDescriptor);
            }
            if (idpSSO != null) {
                break;
            }
        }
        return idpSSO;
    }

    protected IDPSSODescriptorType getIDPSSODescriptor(EntitiesDescriptorType entities) {
        List<Object> entityDescs = entities.getEntityDescriptor();
        for (Object entityDescriptor : entityDescs) {

            if (entityDescriptor instanceof EntitiesDescriptorType) {
                return getIDPSSODescriptor((EntitiesDescriptorType) entityDescriptor);
            }
            return CoreConfigUtil.getIDPDescriptor((EntityDescriptorType) entityDescriptor);
        }
        return null;
    }

    protected IDPSSODescriptorType handleMetadata(EntityDescriptorType entityDescriptor) {
        return CoreConfigUtil.getIDPDescriptor(entityDescriptor);
    }

    protected void initializeHandlerChain() throws ConfigurationException, ProcessingException {
        populateChainConfig();
        SAML2HandlerChainConfig handlerChainConfig = new DefaultSAML2HandlerChainConfig(chainConfigOptions);

        Set<SAML2Handler> samlHandlers = chain.handlers();

        for (SAML2Handler handler : samlHandlers) {
            handler.initChainConfig(handlerChainConfig);
        }
    }

    protected void populateChainConfig() throws ConfigurationException, ProcessingException {
        chainConfigOptions.put(GeneralConstants.CONFIGURATION, spConfiguration);
        chainConfigOptions.put(GeneralConstants.ROLE_VALIDATOR_IGNORE, "false"); // No validator as tomcat realm does validn

        if (doSupportSignature()) {
            chainConfigOptions.put(GeneralConstants.KEYPAIR, keyManager.getSigningKeyPair());
            //If there is a need for X509Data in signedinfo
            String certificateAlias = (String)keyManager.getAdditionalOption(GeneralConstants.X509CERTIFICATE);
            if(certificateAlias != null){
                chainConfigOptions.put(GeneralConstants.X509CERTIFICATE, keyManager.getCertificate(certificateAlias));
            }
        }
    }

    private boolean isGlobalLogout(HttpServletRequest request) {
        String gloStr = request.getParameter(GeneralConstants.GLOBAL_LOGOUT);
        return isNotNull(gloStr) && "true".equalsIgnoreCase(gloStr);
    }

    private String getSAMLVersion(HttpServletRequest request) {
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);
        String version;

        try {
            Document samlDocument = toSAMLResponseDocument(samlResponse, "POST".equalsIgnoreCase(request.getMethod()));
            Element element = samlDocument.getDocumentElement();

            // let's try SAML 2.0 Version attribute first
            version = element.getAttribute("Version");

            if (isNullOrEmpty(version)) {
                // fallback to SAML 1.1 Minor and Major attributes
                String minorVersion = element.getAttribute("MinorVersion");
                String majorVersion = element.getAttribute("MajorVersion");

                version = minorVersion + "." + majorVersion;
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not extract version from SAML Response.", e);
        }

        return version;
    }

    private Document toSAMLResponseDocument(String samlResponse, boolean isPostBinding) throws ParsingException {
        InputStream dataStream = null;

        if (isPostBinding) {
            // deal with SAML response from IDP
            dataStream = PostBindingUtil.base64DecodeAsStream(samlResponse);
        } else {
            // deal with SAML response from IDP
            dataStream = RedirectBindingUtil.base64DeflateDecode(samlResponse);
        }

        try {
            return DocumentUtil.getDocument(dataStream);
        } catch (Exception e) {
            logger.samlResponseFromIDPParsingFailed();
            throw new ParsingException("", e);
        }
    }

    public AuthenticationMechanismOutcome handleSAML11UnsolicitedResponse(HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext) {
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

        Principal principal = request.getUserPrincipal();

        // See if we got a response from IDP
        if (isNotNull(samlResponse)) {
            try {
                InputStream base64DecodedResponse = null;

                if ("GET".equalsIgnoreCase(request.getMethod())) {
                    base64DecodedResponse = RedirectBindingUtil.base64DeflateDecode(samlResponse);
                } else {
                    base64DecodedResponse = PostBindingUtil.base64DecodeAsStream(samlResponse);
                }

                SAMLParser parser = new SAMLParser();
                SAML11ResponseType saml11Response = (SAML11ResponseType) parser.parse(base64DecodedResponse);

                List<SAML11AssertionType> assertions = saml11Response.get();

                if (assertions.size() > 1) {
                    logger.trace("More than one assertion from IDP. Considering the first one.");
                }

                List<String> roles = new ArrayList<String>();
                SAML11AssertionType assertion = assertions.get(0);

                if (assertion != null) {
                    // Get the subject
                    List<SAML11StatementAbstractType> statements = assertion.getStatements();
                    for (SAML11StatementAbstractType statement : statements) {
                        if (statement instanceof SAML11AuthenticationStatementType) {
                            SAML11AuthenticationStatementType subStat = (SAML11AuthenticationStatementType) statement;
                            SAML11SubjectType subject = subStat.getSubject();
                            principal = new SerializablePrincipal(subject.getChoice().getNameID().getValue());
                        }
                    }
                    roles = AssertionUtil.getRoles(assertion, null);
                }

                String username = principal.getName();
                String password = EMPTY_PASSWORD;

                if (logger.isTraceEnabled()) {
                    logger.trace("Roles determined for username=" + username + "=" + Arrays.toString(roles.toArray()));
                }

                ServiceProviderSAMLContext.push(username, roles);

                //TODO: figure out getting the principal via authentication
                IdentityManager identityManager = securityContext.getIdentityManager();

                final Principal userPrincipal = principal;

                Account account = new AccountImpl(userPrincipal, new HashSet<String>(roles), password);

                account = identityManager.verify(account);

                //Register the principal with the request
                register(securityContext, account);

                if (enableAudit) {
                    PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                    auditEvent.setType(PicketLinkAuditEventType.RESPONSE_FROM_IDP);
                    auditEvent.setSubjectName(username);
                    auditEvent.setWhoIsAuditing(servletContext.getContextPath());
                    auditHelper.audit(auditEvent);
                }

                return AuthenticationMechanismOutcome.AUTHENTICATED;
            } catch (Exception e) {
                logger.samlSPHandleRequestError(e);
            }
        }

        return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
    }

}