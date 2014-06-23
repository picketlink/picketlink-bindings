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
package org.picketlink.identity.federation.bindings.jetty.sp;

import static org.picketlink.common.constants.GeneralConstants.CONFIG_FILE_LOCATION;
import static org.picketlink.common.util.StringUtil.isNotNull;
import static org.picketlink.common.util.StringUtil.isNullOrEmpty;

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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Subject;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.util.MultiMap;
import org.eclipse.jetty.util.URIUtil;
import org.jboss.security.audit.AuditLevel;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
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
import org.picketlink.identity.federation.core.saml.v2.util.HandlerUtil;
import org.picketlink.identity.federation.core.saml.workflow.ServiceProviderSAMLWorkflow;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntitiesDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.web.config.AbstractSAMLConfigurationProvider;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.process.ServiceProviderBaseProcessor;
import org.picketlink.identity.federation.web.process.ServiceProviderSAMLRequestProcessor;
import org.picketlink.identity.federation.web.process.ServiceProviderSAMLResponseProcessor;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;
import org.w3c.dom.Document;

/**
 * @author Anil Saldhana
 * @since December 09, 2013
 */
public class SPFormAuthenticator extends FormAuthenticator {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    protected transient String samlHandlerChainClass = null;

    protected ServletContext theServletContext = null;

    protected Map<String, Object> chainConfigOptions = new HashMap<String, Object>();
    /**
     * The user can inject a fully qualified name of a
     * {@link org.picketlink.identity.federation.web.util.SAMLConfigurationProvider}
     */
    protected SAMLConfigurationProvider configProvider = null;
    /**
     * If the service provider is configured with an IDP metadata file, then this certificate can be picked up from the metadata
     */
    protected transient X509Certificate idpCertificate = null;
    protected int timerInterval = -1;

    protected Timer timer = null;

    public static final String EMPTY_PASSWORD = "EMPTY_STR";

    protected boolean enableAudit = false;

    public static final String FORM_PRINCIPAL_NOTE = "picketlink.form.principal";
    public static final String FORM_ROLES_NOTE = "picketlink.form.roles";
    public static final String FORM_REQUEST_NOTE = "picketlink.REQUEST";

    public static final String logoutPage = "/logout.html"; // get from configuration

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

    protected PicketLinkAuditHelper auditHelper = null;
    protected TrustKeyManager keyManager;

    public SPFormAuthenticator() {
    }

    public SPFormAuthenticator(String login, String error, boolean dispatch) {
        super(login, error, dispatch);
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        super.setConfiguration(configuration);
        String contextPath = ContextHandler.getCurrentContext().getContextPath();
        theServletContext = ContextHandler.getCurrentContext().getContext(contextPath);
        startPicketLink();
    }

    @Override
    public Authentication validateRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory)
            throws ServerAuthException {
        // TODO: Deal with character encoding
        // request.setCharacterEncoding(xyz)

        String contextPath = ContextHandler.getCurrentContext().getContextPath();
        theServletContext = ContextHandler.getCurrentContext().getContext(contextPath);

        // Get the session
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        HttpSession session = request.getSession();

        System.out.println("Request ID=" + servletRequest.toString());
        System.out.println("Session ID=" + session.getId());

        // check if this call is resulting from the redirect after successful authentication.
        // if so, make the authentication successful and continue the original request
        if (saveRestoreRequest && matchRequest(request)) {
            Principal savedPrincipal = (Principal) session.getAttribute(FORM_PRINCIPAL_NOTE);
            List<String> savedRoles = (List<String>) session.getAttribute(FORM_ROLES_NOTE);
            Authentication registeredAuthentication = register(request, savedPrincipal, savedRoles);

            // try to restore the original request (including post data, etc...)
            if (restoreRequest(request, session)) {
                // success! user is authenticated; continue processing original request
                return registeredAuthentication;
            } else {
                // no saved request found...
                return Authentication.UNAUTHENTICATED;
            }
        }
        ServiceProviderSAMLWorkflow serviceProviderSAMLWorkflow = new ServiceProviderSAMLWorkflow();
        serviceProviderSAMLWorkflow.setRedirectionHandler(new JettyRedirectionHandler());

        // Eagerly look for Local LogOut
        boolean localLogout = serviceProviderSAMLWorkflow.isLocalLogoutRequest(request);

        if (localLogout) {
            try {
                serviceProviderSAMLWorkflow.sendToLogoutPage(request, response, session, theServletContext, logoutPage);
            } catch (ServletException e) {
                logger.samlLogoutError(e);
                throw new RuntimeException(e);
            } catch (IOException e1) {
                logger.samlLogoutError(e1);
                throw new RuntimeException(e1);
            }
            return Authentication.UNAUTHENTICATED;
        }

        String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

        Principal principal = request.getUserPrincipal();

        try {
            // If we have already authenticated the user and there is no request from IDP or logout from user
            if (principal != null
                    && !(serviceProviderSAMLWorkflow.isLocalLogoutRequest(request) || isNotNull(samlRequest) || isNotNull(samlResponse)))
                return Authentication.SEND_SUCCESS;

            // General User Request
            if (!isNotNull(samlRequest) && !isNotNull(samlResponse)) {
                return generalUserRequest(servletRequest, servletResponse, mandatory);
            }

            // Handle a SAML Response from IDP
            if (isNotNull(samlResponse)) {
                return handleSAMLResponse(servletRequest, servletResponse, mandatory);
            }

            // Handle SAML Requests from IDP
            if (isNotNull(samlRequest)) {
                return handleSAMLRequest(servletRequest, servletResponse, mandatory);
            }// end if

            // local authentication
            return localAuthentication(servletRequest, servletResponse, mandatory);
        } catch (IOException e) {
            if (StringUtil.isNotNull(spConfiguration.getErrorPage())) {
                try {
                    request.getRequestDispatcher(spConfiguration.getErrorPage()).forward(request, response);
                } catch (ServletException e1) {
                    logger.samlErrorPageForwardError(spConfiguration.getErrorPage(), e1);
                } catch (IOException e1) {
                    logger.samlErrorPageForwardError(spConfiguration.getErrorPage(), e1);
                }
                return Authentication.UNAUTHENTICATED;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Handle the user invocation for the first time
     *
     * @param servletRequest
     * @param servletResponse
     * @param mandatory
     * @return
     * @throws IOException
     */
    private Authentication generalUserRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory)
            throws IOException, ServerAuthException {
        //only perform SAML Authentication if it is mandatory
        if(!mandatory){
            Request request = (Request) servletRequest;
            return request.getAuthentication();
        }
        ServiceProviderSAMLWorkflow serviceProviderSAMLWorkflow = new ServiceProviderSAMLWorkflow();
        serviceProviderSAMLWorkflow.setRedirectionHandler(new JettyRedirectionHandler());

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        HttpSession session = request.getSession(false);
        boolean willSendRequest = false;

        HTTPContext httpContext = new HTTPContext(request, response, theServletContext);
        Set<SAML2Handler> handlers = chain.handlers();

        boolean postBinding = spConfiguration.getBindingType().equals("POST");

        // Neither saml request nor response from IDP
        // So this is a user request
        SAML2HandlerResponse saml2HandlerResponse = null;
        try {
            ServiceProviderBaseProcessor baseProcessor = new ServiceProviderBaseProcessor(postBinding, serviceURL,
                    this.picketLinkConfiguration);
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
                    this.saveRequest(request, session);
                }
                if (enableAudit) {
                    PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                    auditEvent.setType(PicketLinkAuditEventType.REQUEST_TO_IDP);
                    auditEvent.setWhoIsAuditing(theServletContext.getContextPath());
                    auditHelper.audit(auditEvent);
                }
                serviceProviderSAMLWorkflow.sendRequestToIDP(destination, samlResponseDocument, relayState, response,
                        willSendRequest, destinationQueryStringWithSignature, isHttpPostBinding());
                return Authentication.SEND_CONTINUE;
            } catch (Exception e) {
                logger.samlSPHandleRequestError(e);
                throw logger.samlSPProcessingExceptionError(e);
            }
        }

        return localAuthentication(servletRequest, servletResponse, mandatory);
    }

    protected boolean matchRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        synchronized (session) {
            String j_uri = (String) session.getAttribute(__J_URI);
            if (j_uri != null) {
                // check if the request is for the same url as the original and restore
                // params if it was a post
                StringBuffer buf = request.getRequestURL();
                if (request.getQueryString() != null)
                    buf.append("?").append(request.getQueryString());

                if (j_uri.equals(buf.toString())) {
                    return true;
                }
            }
            return false;
        }
    }

    protected Authentication register(HttpServletRequest httpServletRequest, Principal principal, List<String> roles) {
        if (roles == null) {
            roles = new ArrayList<String>();
        }
        HttpSession session = httpServletRequest.getSession(false);
        session.setAttribute(FORM_PRINCIPAL_NOTE, principal);
        session.setAttribute(FORM_ROLES_NOTE, roles);
        Request request = (Request) httpServletRequest;
        Authentication authentication = request.getAuthentication();
        if (!(authentication instanceof UserAuthentication)) {
            Subject theSubject = new Subject();
            String[] theRoles = new String[roles.size()];
            roles.toArray(theRoles);

            UserIdentity userIdentity = new DefaultUserIdentity(theSubject, principal, theRoles);
            authentication = new UserAuthentication(getAuthMethod(), userIdentity);
            request.setAuthentication(authentication);
        }
        return authentication;
    }

    protected boolean restoreRequest(HttpServletRequest request, HttpSession session) {
        synchronized (session) {
            String j_uri = (String) session.getAttribute(__J_URI);
            if (j_uri != null) {
                // check if the request is for the same url as the original and restore
                // params if it was a post
                StringBuffer buf = request.getRequestURL();
                if (request.getQueryString() != null)
                    buf.append("?").append(request.getQueryString());

                /*
                 * if (j_uri.equals(buf.toString())) {
                 */
                MultiMap<String> j_post = (MultiMap<String>) session.getAttribute(__J_POST);
                if (j_post != null) {
                    Request base_request = HttpChannel.getCurrentHttpChannel().getRequest();
                    base_request.setParameters(j_post);
                }
                session.removeAttribute(__J_URI);
                session.removeAttribute(__J_METHOD);
                session.removeAttribute(__J_POST);
                // }
                return true;
            }
            return false;
        }
    }

    protected void saveRequest(HttpServletRequest request, HttpSession session) {
        // remember the current URI
        synchronized (session) {
            // But only if it is not set already, or we save every uri that leads to a login form redirect
            if (session.getAttribute(__J_URI) == null) {
                StringBuffer buf = request.getRequestURL();
                if (request.getQueryString() != null)
                    buf.append("?").append(request.getQueryString());
                session.setAttribute(__J_URI, buf.toString());
                session.setAttribute(__J_METHOD, request.getMethod());

                if (MimeTypes.Type.FORM_ENCODED.is(request.getContentType()) && HttpMethod.POST.is(request.getMethod())) {
                    Request base_request = (request instanceof Request) ? (Request) request : HttpChannel
                            .getCurrentHttpChannel().getRequest();
                    base_request.extractParameters();
                    session.setAttribute(__J_POST, new MultiMap<String>(base_request.getParameters()));
                }
            }
        }
    }

    /**
     * Fall back on local authentication at the service provider side
     *
     * @param servletRequest
     * @param servletRequest
     * @param mandatory
     * @return
     * @throws IOException
     */
    protected Authentication localAuthentication(ServletRequest servletRequest, ServletResponse servletResponse,
            boolean mandatory) throws IOException, ServerAuthException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (request.getUserPrincipal() == null) {
            logger.samlSPFallingBackToLocalFormAuthentication();// fallback
            try {
                return super.validateRequest(servletRequest, servletResponse, mandatory);
            } catch (NoSuchMethodError e) {
                /*
                 * // Use Reflection try { Method method = super.getClass().getMethod("authenticate", new Class[] {
                 * HttpServletRequest.class, HttpServletResponse.class, LoginConfig.class }); return (Boolean)
                 * method.invoke(this, new Object[] { request.getRequest(), response.getResponse(), loginConfig }); } catch
                 * (Exception ex) { throw logger.unableLocalAuthentication(ex); }
                 */
            }
        } else {
            return Authentication.SEND_SUCCESS;
        }
        return Authentication.UNAUTHENTICATED;
    }

    /**
     * Handle the IDP Request
     *
     * @param servletRequest
     * @param servletResponse
     * @param mandatory
     * @return
     * @throws IOException
     */
    private Authentication handleSAMLRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory)
            throws IOException, ServerAuthException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
        HTTPContext httpContext = new HTTPContext(request, response, theServletContext);
        Set<SAML2Handler> handlers = chain.handlers();

        try {
            ServiceProviderSAMLRequestProcessor requestProcessor = new ServiceProviderSAMLRequestProcessor(request.getMethod()
                    .equals("POST"), this.serviceURL, this.picketLinkConfiguration);
            requestProcessor.setTrustKeyManager(keyManager);
            boolean result = requestProcessor.process(samlRequest, httpContext, handlers, chainLock);

            if (enableAudit) {
                PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                auditEvent.setType(PicketLinkAuditEventType.REQUEST_FROM_IDP);
                auditEvent.setWhoIsAuditing(theServletContext.getContextPath());
                auditHelper.audit(auditEvent);
            }

            // If response is already commited, we need to stop with processing of HTTP request
            if (response.isCommitted())
                return Authentication.UNAUTHENTICATED;

            if (result)
                return Authentication.SEND_SUCCESS;
        } catch (Exception e) {
            logger.samlSPHandleRequestError(e);
            throw logger.samlSPProcessingExceptionError(e);
        }

        return localAuthentication(servletRequest, servletResponse, mandatory);
    }

    /**
     * Handle IDP Response
     *
     * @param servletRequest
     * @param servletResponse
     * @return
     * @throws IOException
     */
    private Authentication handleSAMLResponse(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory)
            throws IOException, ServerAuthException {
        ServiceProviderSAMLWorkflow serviceProviderSAMLWorkflow = new ServiceProviderSAMLWorkflow();
        serviceProviderSAMLWorkflow.setRedirectionHandler(new JettyRedirectionHandler());

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        HttpSession session = request.getSession(false);
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

        boolean willSendRequest = false;
        HTTPContext httpContext = new HTTPContext(request, response, theServletContext);
        Set<SAML2Handler> handlers = chain.handlers();

        Principal principal = request.getUserPrincipal();

        if (!serviceProviderSAMLWorkflow.validate(request)) {
            throw new IOException(ErrorCodes.VALIDATION_CHECK_FAILED);
        }

        // deal with SAML response from IDP
        try {
            ServiceProviderSAMLResponseProcessor responseProcessor = new ServiceProviderSAMLResponseProcessor(request
                    .getMethod().equals("POST"), serviceURL, this.picketLinkConfiguration);
            if (auditHelper != null) {
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
                serviceProviderSAMLWorkflow.sendRequestToIDP(destination, samlResponseDocument, relayState, response,
                        willSendRequest, destinationQueryStringWithSignature, spConfiguration.getBindingType()
                                .equalsIgnoreCase("POST"));
            } else {
                // See if the session has been invalidated
                boolean sessionValidity = sessionIsValid(session);

                if (!sessionValidity) {
                    serviceProviderSAMLWorkflow.sendToLogoutPage(request, response, session, theServletContext, logoutPage);
                    return Authentication.UNAUTHENTICATED;
                }

                // We got a response with the principal
                List<String> roles = saml2HandlerResponse.getRoles();
                if (principal == null)
                    principal = (Principal) session.getAttribute(GeneralConstants.PRINCIPAL_ID);

                String username = principal.getName();
                String password = EMPTY_PASSWORD;

                if (logger.isTraceEnabled()) {
                    logger.trace("Roles determined for username=" + username + "=" + Arrays.toString(roles.toArray()));
                }

                // TODO: figure out getting the principal via authentication

                /*
                 * // Map to JBoss specific principal if ((new ServerDetector()).isJboss() || jbossEnv) { // Push a context
                 * ServiceProviderSAMLContext.push(username, roles); principal = context.getRealm().authenticate(username,
                 * password); ServiceProviderSAMLContext.clear(); } else { // tomcat env principal =
                 * getGenericPrincipal(request, username, roles); }
                 */

                // Register the principal with the request
                Authentication registeredAuthentication = register(request, principal, roles);

                if (enableAudit) {
                    PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent(AuditLevel.INFO);
                    auditEvent.setType(PicketLinkAuditEventType.RESPONSE_FROM_IDP);
                    auditEvent.setSubjectName(username);
                    auditEvent.setWhoIsAuditing(theServletContext.getContextPath());
                    auditHelper.audit(auditEvent);
                }

                // Redirect the user to the originally requested URL
                if (saveRestoreRequest) {

                    // Redirect to original request
                    String nuri;
                    synchronized (session) {
                        nuri = (String) session.getAttribute(__J_URI);

                        if (nuri == null || nuri.length() == 0) {
                            nuri = request.getContextPath();
                            if (nuri.length() == 0)
                                nuri = URIUtil.SLASH;
                        }
                    }

                    response.setContentLength(0);
                    Response base_response = HttpChannel.getCurrentHttpChannel().getResponse();
                    Request base_request = HttpChannel.getCurrentHttpChannel().getRequest();
                    int redirectCode = (base_request.getHttpVersion().getVersion() < HttpVersion.HTTP_1_1.getVersion() ? HttpServletResponse.SC_MOVED_TEMPORARILY
                            : HttpServletResponse.SC_SEE_OTHER);
                    base_response.sendRedirect(redirectCode, response.encodeRedirectURL(nuri));
                    return Authentication.SEND_SUCCESS; //since a redirect was made to the original requested URL inform Jetty the response has already been handled

                    // restoreRequest(request,session);

                    /*
                     * // Store the authenticated principal in the session. session.setAttribute(FORM_PRINCIPAL_NOTE,
                     * principal);
                     *
                     * // Redirect to the original URL. Note that this will trigger the // authenticator again, but on
                     * resubmission we will look in the // session notes to retrieve the authenticated principal and // prevent
                     * reauthentication String requestURI = savedRequestURL(session);
                     *
                     * if (requestURI == null) { requestURI = spConfiguration.getServiceURL(); }
                     *
                     * logger.trace("Redirecting back to original Request URI: " + requestURI);
                     * response.sendRedirect(response.encodeRedirectURL(requestURI)); return Authentication.UNAUTHENTICATED;
                     */
                }
                // register(request, principal, null);
                return registeredAuthentication;
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
                return generalUserRequest(servletRequest, servletResponse, mandatory);
            }
            logger.samlSPHandleRequestError(pe);
            throw logger.samlSPProcessingExceptionError(pe);
        } catch (Exception e) {
            logger.samlSPHandleRequestError(e);
            throw logger.samlSPProcessingExceptionError(e);
        }

        return localAuthentication(servletRequest, servletResponse, mandatory);
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

    protected boolean sessionIsValid(HttpSession session) {
        try {
            long sessionTime = session.getCreationTime();
        } catch (IllegalStateException ise) {
            return false;
        }
        return true;
    }

    protected String savedRequestURL(HttpSession session) {
        StringBuilder builder = new StringBuilder();
        HttpServletRequest request = (HttpServletRequest) session.getAttribute(FORM_REQUEST_NOTE);
        if (request != null) {
            builder.append(request.getRequestURI());
            if (request.getQueryString() != null) {
                builder.append("?").append(request.getQueryString());
            }
        }
        return builder.toString();
    }

    protected void startPicketLink() {
        SystemPropertiesUtil.ensure();
        Handlers handlers = null;

        // Introduce a timer to reload configuration if desired
        if (timerInterval > 0) {
            if (timer == null) {
                timer = new Timer();
            }
            timer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    processConfiguration();
                    initKeyProvider(theServletContext);
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
                handlers = ConfigurationUtil.getHandlers(theServletContext.getResourceAsStream(handlerConfigFileName));
            }

            chain.addAll(HandlerUtil.getHandlers(handlers));

            this.initKeyProvider(theServletContext);
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
    }

    /**
     * <p>
     * Initialize the KeyProvider configurations. This configurations are to be used during signing and validation of SAML
     * assertions.
     * </p>
     *
     * @param context
     */
    protected void initKeyProvider(ServletContext context) {
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

            // Special case when you need X509Data in SignedInfo
            if (authProperties != null) {
                for (AuthPropertyType authPropertyType : authProperties) {
                    String key = authPropertyType.getKey();
                    if (GeneralConstants.X509CERTIFICATE.equals(key)) {
                        // we need X509Certificate in SignedInfo. The value is the alias name
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
            is = theServletContext.getResourceAsStream(this.configFile);
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
                        is = theServletContext.getResourceAsStream(GeneralConstants.DEPRECATED_CONFIG_FILE_LOCATION);

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
                    is = theServletContext.getResourceAsStream(GeneralConstants.DEPRECATED_CONFIG_FILE_LOCATION);
                    if (is == null)
                        throw logger.configurationFileMissing(configFile);
                    spConfiguration = ConfigurationUtil.getSPConfiguration(is);
                }
            }

            if (this.picketLinkConfiguration != null) {
                enableAudit = picketLinkConfiguration.isEnableAudit();

                // See if we have the system property enabled
                if (!enableAudit) {
                    String sysProp = SecurityActions.getSystemProperty(GeneralConstants.AUDIT_ENABLE, "NULL");
                    if (!"NULL".equals(sysProp)) {
                        enableAudit = Boolean.parseBoolean(sysProp);
                    }
                }

                if (enableAudit) {
                    if (auditHelper == null) {
                        String securityDomainName = PicketLinkAuditHelper.getSecurityDomainName(theServletContext);

                        auditHelper = new PicketLinkAuditHelper(securityDomainName);
                    }
                }
            }

            if (StringUtil.isNotNull(spConfiguration.getIdpMetadataFile())) {
                processIDPMetadataFile(spConfiguration.getIdpMetadataFile());
            } else {
                this.identityURL = spConfiguration.getIdentityURL();
            }
            this.serviceURL = spConfiguration.getServiceURL();
            this.canonicalizationMethod = spConfiguration.getCanonicalizationMethod();

            logger.samlSPSettingCanonicalizationMethod(canonicalizationMethod);
            XMLSignatureUtil.setCanonicalizationMethodType(canonicalizationMethod);

            logger.trace("Identity Provider URL=" + this.identityURL);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Attempt to process a metadata file available locally
     */
    protected void processIDPMetadataFile(String idpMetadataFile) {
        InputStream is = theServletContext.getResourceAsStream(idpMetadataFile);
        if (is == null)
            return;

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
            return;
        }
        List<EndpointType> endpoints = idpSSO.getSingleSignOnService();
        for (EndpointType endpoint : endpoints) {
            String endpointBinding = endpoint.getBinding().toString();
            if (endpointBinding.contains("HTTP-POST"))
                endpointBinding = "POST";
            else if (endpointBinding.contains("HTTP-Redirect"))
                endpointBinding = "REDIRECT";
            if (spConfiguration.getBindingType().equals(endpointBinding)) {
                identityURL = endpoint.getLocation().toString();
                break;
            }
        }
        List<KeyDescriptorType> keyDescriptors = idpSSO.getKeyDescriptor();
        if (keyDescriptors.size() > 0) {
            this.idpCertificate = MetaDataExtractor.getCertificate(keyDescriptors.get(0));
        }
    }

    protected IDPSSODescriptorType handleMetadata(EntitiesDescriptorType entities) {
        IDPSSODescriptorType idpSSO = null;

        List<Object> entityDescs = entities.getEntityDescriptor();
        for (Object entityDescriptor : entityDescs) {
            if (entityDescriptor instanceof EntitiesDescriptorType) {
                idpSSO = getIDPSSODescriptor(entities);
            } else
                idpSSO = handleMetadata((EntityDescriptorType) entityDescriptor);
            if (idpSSO != null)
                break;
        }
        return idpSSO;
    }

    protected IDPSSODescriptorType handleMetadata(EntityDescriptorType entityDescriptor) {
        return CoreConfigUtil.getIDPDescriptor(entityDescriptor);
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
            // If there is a need for X509Data in signedinfo
            String certificateAlias = (String) keyManager.getAdditionalOption(GeneralConstants.X509CERTIFICATE);
            if (certificateAlias != null) {
                chainConfigOptions.put(GeneralConstants.X509CERTIFICATE, keyManager.getCertificate(certificateAlias));
            }
        }
    }

    /**
     * An instance of {@link org.picketlink.identity.federation.core.saml.workflow.ServiceProviderSAMLWorkflow.RedirectionHandler}
     * that performs JETTY specific redirection and post workflows
     */
    public class JettyRedirectionHandler extends ServiceProviderSAMLWorkflow.RedirectionHandler {
        @Override
        public void sendRedirectForRequestor(String destination, HttpServletResponse response) throws IOException {
            common(destination, response);
            response.setHeader("Cache-Control", "no-cache, no-store");
            sendRedirect(response, destination);
        }

        @Override
        public void sendRedirectForResponder(String destination, HttpServletResponse response) throws IOException {
            common(destination, response);
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate,private");
            sendRedirect(response, destination);
        }

        private void common(String destination, HttpServletResponse response) {
            response.setCharacterEncoding("UTF-8");
            response.setHeader("Location", destination);
            response.setHeader("Pragma", "no-cache");
        }

        private void sendRedirect(HttpServletResponse response, String destination) throws IOException {
            // response.reset();
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
            response.sendRedirect(destination);
        }
    }
}
