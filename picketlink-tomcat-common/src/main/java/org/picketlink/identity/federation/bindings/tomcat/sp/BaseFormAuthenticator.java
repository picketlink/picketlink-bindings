package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.SystemPropertiesUtil;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.handler.Handlers;
import org.picketlink.identity.federation.api.saml.v2.metadata.MetaDataExtractor;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.factories.SAML2HandlerChainFactory;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChain;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.util.HandlerUtil;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntitiesDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.web.config.AbstractSAMLConfigurationProvider;
import org.picketlink.identity.federation.web.core.SessionManager;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;
import org.w3c.dom.Document;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionListener;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.HashMap;
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
 * Base Class for Service Provider Form Authenticators
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jun 9, 2009
 */
public abstract class BaseFormAuthenticator extends FormAuthenticator {

    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    protected volatile PicketLinkAuditHelper auditHelper = null;

    protected volatile TrustKeyManager keyManager;

    protected volatile PicketLinkType picketLinkConfiguration = null;

    protected volatile String serviceURL = null;

    protected volatile String issuerID = null;

    protected String configFile;

    /**
     * If the service provider is configured with an IDP metadata file, then this certificate can be picked up from the metadata
     */
    protected transient X509Certificate idpCertificate = null;

    protected transient SAML2HandlerChain chain = null;

    protected transient String samlHandlerChainClass = null;

    protected Map<String, Object> chainConfigOptions;

    // Whether the authenticator has to to save and restore request
    protected boolean saveRestoreRequest = true;

    /**
     * A Lock for Handler operations in the chain
     */
    protected Lock chainLock = new ReentrantLock();

    protected volatile String canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;

    /**
     * The user can inject a fully qualified name of a {@link SAMLConfigurationProvider}
     */
    protected SAMLConfigurationProvider configProvider = null;

    /**
     * Servlet3 related changes forced Tomcat to change the authenticate method signature in the FormAuthenticator. For now, we use
     * reflection for forward compatibility. This has to be changed in future.
     */
    private Method theSuperRegisterMethod = null;

    /**
     * If it is determined that we are running in a Tomcat6/JBAS5 environment, there is no need to seek the super.register method
     * that conforms to the servlet3 spec changes
     */
    private boolean seekSuperRegisterMethod = true;

    protected int timerInterval = -1;

    protected Timer timer = null;
    protected IDPSSODescriptorType idpMetadata;

    public BaseFormAuthenticator() {
        super();
    }

    protected String idpAddress = null;

    /**
     * If the request.getRemoteAddr is not exactly the IDP address that you have keyed in your deployment descriptor for keystore
     * alias, you can set it here explicitly
     */
    public void setIdpAddress(String idpAddress) {
        this.idpAddress = idpAddress;
    }

    /**
     * Get the name of the configuration file
     *
     * @return
     */
    public String getConfigFile() {
        return configFile;
    }

    /**
     * Set the name of the configuration file
     *
     * @param configFile
     */
    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    /**
     * Set the SAML Handler Chain Class fqn
     *
     * @param samlHandlerChainClass
     */
    public void setSamlHandlerChainClass(String samlHandlerChainClass) {
        this.samlHandlerChainClass = samlHandlerChainClass;
    }

    /**
     * Set the service URL
     *
     * @param serviceURL
     */
    public void setServiceURL(String serviceURL) {
        this.serviceURL = serviceURL;
    }

    /**
     * Set whether the authenticator saves/restores the request during form authentication
     *
     * @param saveRestoreRequest
     */
    public void setSaveRestoreRequest(boolean saveRestoreRequest) {
        this.saveRestoreRequest = saveRestoreRequest;
    }

    /**
     * Set the {@link SAMLConfigurationProvider} fqn
     *
     * @param configProviderFQN fqn of a {@link SAMLConfigurationProvider}
     */
    public void setConfigProvider(String configProviderFQN) {
        if (configProviderFQN == null) {
            throw logger.nullValueError("cp");
        }
        Class<?> clazz = SecurityActions.loadClass(getClass(), configProviderFQN);
        if (clazz == null) {
            throw logger.nullValueError("clazz");
        }
        try {
            configProvider = (SAMLConfigurationProvider) clazz.newInstance();
        } catch (Exception e) {
            throw logger.runtimeException(ErrorCodes.CANNOT_CREATE_INSTANCE + configProviderFQN + ":" + e.getMessage(), e);
        }
    }

    /**
     * Set an instance of the {@link SAMLConfigurationProvider}
     *
     * @param configProvider
     */
    public void setConfigProvider(SAMLConfigurationProvider configProvider) {
        this.configProvider = configProvider;
    }

    /**
     * Get the {@link SPType}
     *
     * @return
     */
    public SPType getConfiguration() {
        return (SPType) this.picketLinkConfiguration.getIdpOrSP();
    }

    /**
     * Set a separate issuer id
     *
     * @param issuerID
     */
    public void setIssuerID(String issuerID) {
        this.issuerID = issuerID;
    }

    /**
     * Set the logout page
     *
     * @param logOutPage
     */
    public void setLogOutPage(String logOutPage) {
        logger.warn("Option logOutPage is now configured with the PicketLinkSP element.");
    }

    /**
     * Set the Timer Value to reload the configuration
     *
     * @param value an integer value that represents timer value (in miliseconds)
     */
    public void setTimerInterval(String value) {
        if (isNotNull(value)) {
            timerInterval = Integer.parseInt(value);
        }
    }

    /**
     * Perform validation os the request object
     *
     * @param request
     *
     * @return
     */
    protected boolean validate(Request request) {
        return request.getParameter("SAMLResponse") != null;
    }

    /**
     * Get the Identity URL
     *
     * @return
     */
    public String getIdentityURL() {
        return getConfiguration().getIdentityURL();
    }

    /**
     * Get the {@link X509Certificate} of the IDP if provided via the IDP metadata file
     *
     * @return {@link X509Certificate} or null
     */
    public X509Certificate getIdpCertificate() {
        return idpCertificate;
    }

    /**
     * This method is a hack!!! Tomcat on account of Servlet3 changed their authenticator method signatures We utilize Java
     * Reflection to identify the super register method on the first call and save it. Subsquent invocations utilize the saved
     * {@link Method}
     *
     * @see org.apache.catalina.authenticator.AuthenticatorBase#register(org.apache.catalina.connector.Request,
     * org.apache.catalina.connector.Response, java.security.Principal, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    protected void register(Request request, Response response, Principal principal, String arg3, String arg4, String arg5) {
        // Try the JBossAS6 version
        if (theSuperRegisterMethod == null && seekSuperRegisterMethod) {
            Class<?>[] args = new Class[]{Request.class, HttpServletResponse.class, Principal.class, String.class,
                String.class, String.class};
            Class<?> superClass = getAuthenticatorBaseClass();
            theSuperRegisterMethod = SecurityActions.getMethod(superClass, "register", args);
        }
        try {
            if (theSuperRegisterMethod != null) {
                Object[] callArgs = new Object[]{request, response, principal, arg3, arg4, arg5};
                theSuperRegisterMethod.invoke(this, callArgs);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Try the older version
        if (theSuperRegisterMethod == null) {
            seekSuperRegisterMethod = false; // Don't try to seek super register method on next invocation
            super.register(request, response, principal, arg3, arg4, arg5);
            return;
        }
    }

    /**
     * Fall back on local authentication at the service provider side
     *
     * @param request
     * @param response
     * @param loginConfig
     *
     * @return
     *
     * @throws IOException
     */
    protected boolean localAuthentication(Request request, Response response, LoginConfig loginConfig) throws IOException {
        if (request.getUserPrincipal() == null) {
            logger.samlSPFallingBackToLocalFormAuthentication();// fallback
            try {
                return super.authenticate(request, response, loginConfig);
            } catch (NoSuchMethodError e) {
                // Use Reflection
                try {
                    Method method = super.getClass().getMethod("authenticate",
                        new Class[]{HttpServletRequest.class, HttpServletResponse.class, LoginConfig.class});
                    return (Boolean) method.invoke(this, new Object[]{request.getRequest(), response.getResponse(),
                        loginConfig});
                } catch (Exception ex) {
                    throw logger.unableLocalAuthentication(ex);
                }
            }
        } else {
            return true;
        }
    }

    /**
     * Return the SAML Binding that this authenticator supports
     *
     * @return
     *
     * @see {@link org.picketlink.common.constants.JBossSAMLURIConstants#SAML_HTTP_POST_BINDING}
     * @see {@link org.picketlink.common.constants.JBossSAMLURIConstants#SAML_HTTP_REDIRECT_BINDING}
     */
    protected abstract String getBinding();

    /**
     * Attempt to process a metadata file available locally
     * @param configuration
     */
    protected IDPSSODescriptorType getIdpMetadataFromFile(SPType configuration) {
        ServletContext servletContext = context.getServletContext();
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

    /**
     * Process the configuration from the configuration file
     */
    @SuppressWarnings("deprecation")
    protected void processConfiguration() {
        ServletContext servletContext = context.getServletContext();
        InputStream is;

        if (isNullOrEmpty(this.configFile)) {
            is = servletContext.getResourceAsStream(CONFIG_FILE_LOCATION);
        } else {
            try {
                is = new FileInputStream(this.configFile);
            } catch (FileNotFoundException e) {
                throw logger.samlIDPConfigurationError(e);
            }
        }

        PicketLinkType picketLinkType;

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

                    picketLinkType = configProvider.getPicketLinkConfiguration();
                    picketLinkType.setIdpOrSP(configProvider.getSPConfiguration());
                } catch (ProcessingException e) {
                    throw logger.samlSPConfigurationError(e);
                } catch (ParsingException e) {
                    throw logger.samlSPConfigurationError(e);
                }
            } else {
                if (is != null) {
                    try {
                        picketLinkType = ConfigurationUtil.getConfiguration(is);
                    } catch (ParsingException e) {
                        logger.trace(e);
                        throw logger.samlSPConfigurationError(e);
                    }
                } else {
                    is = servletContext.getResourceAsStream(GeneralConstants.DEPRECATED_CONFIG_FILE_LOCATION);
                    if (is == null) {
                        throw logger.configurationFileMissing(configFile);
                    }

                    picketLinkType = new PicketLinkType();

                    picketLinkType.setIdpOrSP(ConfigurationUtil.getSPConfiguration(is));
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

            Boolean enableAudit = picketLinkType.isEnableAudit();

            //See if we have the system property enabled
            if (!enableAudit) {
                String sysProp = SecurityActions.getSystemProperty(GeneralConstants.AUDIT_ENABLE, "NULL");
                if (!"NULL".equals(sysProp)) {
                    enableAudit = Boolean.parseBoolean(sysProp);
                }
            }

            if (enableAudit) {
                if (auditHelper == null) {
                    String securityDomainName = PicketLinkAuditHelper.getSecurityDomainName(servletContext);

                    auditHelper = new PicketLinkAuditHelper(securityDomainName);
                }
            }

            SPType spConfiguration = (SPType) picketLinkType.getIdpOrSP();
            processIdPMetadata(spConfiguration);

            this.serviceURL = spConfiguration.getServiceURL();
            this.canonicalizationMethod = spConfiguration.getCanonicalizationMethod();
            this.picketLinkConfiguration = picketLinkType;

            logger.samlSPSettingCanonicalizationMethod(canonicalizationMethod);
            XMLSignatureUtil.setCanonicalizationMethodType(canonicalizationMethod);

            try {
                this.initKeyProvider(context);
                this.initializeHandlerChain(picketLinkType);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            logger.trace("Identity Provider URL=" + getConfiguration().getIdentityURL());
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
            this.context.getServletContext());

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

    protected void initializeHandlerChain(PicketLinkType picketLinkType) throws Exception {
        SAML2HandlerChain handlerChain;

        // Get the chain from config
        if (isNullOrEmpty(samlHandlerChainClass)) {
            handlerChain = SAML2HandlerChainFactory.createChain();
        } else {
            try {
                handlerChain = SAML2HandlerChainFactory.createChain(this.samlHandlerChainClass);
            } catch (ProcessingException e1) {
                throw new LifecycleException(e1);
            }
        }

        Handlers handlers = picketLinkType.getHandlers();

        if (handlers == null) {
            // Get the handlers
            String handlerConfigFileName = GeneralConstants.HANDLER_CONFIG_FILE_LOCATION;
            ServletContext servletContext = context.getServletContext();
            handlers = ConfigurationUtil.getHandlers(servletContext.getResourceAsStream(handlerConfigFileName));
        }

        picketLinkType.setHandlers(handlers);

        handlerChain.addAll(HandlerUtil.getHandlers(handlers));

        populateChainConfig(picketLinkType);
        SAML2HandlerChainConfig handlerChainConfig = new DefaultSAML2HandlerChainConfig(chainConfigOptions);

        Set<SAML2Handler> samlHandlers = handlerChain.handlers();

        for (SAML2Handler handler : samlHandlers) {
            handler.initChainConfig(handlerChainConfig);
        }

        chain = handlerChain;
    }

    protected void populateChainConfig(PicketLinkType picketLinkType) throws ConfigurationException, ProcessingException {
        Map<String, Object> chainConfigOptions = new HashMap<String, Object>();

        chainConfigOptions.put(GeneralConstants.CONFIGURATION, picketLinkType.getIdpOrSP());
        chainConfigOptions.put(GeneralConstants.ROLE_VALIDATOR_IGNORE, "false"); // No validator as tomcat realm does validn

        if (doSupportSignature()) {
            chainConfigOptions.put(GeneralConstants.KEYPAIR, keyManager.getSigningKeyPair());
            //If there is a need for X509Data in signedinfo
            String certificateAlias = (String) keyManager.getAdditionalOption(GeneralConstants.X509CERTIFICATE);
            if (certificateAlias != null) {
                chainConfigOptions.put(GeneralConstants.X509CERTIFICATE, keyManager.getCertificate(certificateAlias));
            }
        }

        this.chainConfigOptions = chainConfigOptions;
    }

    protected void sendToLogoutPage(Request request, Response response, Session session) throws IOException, ServletException {
        // we are invalidated.
        RequestDispatcher dispatch = context.getServletContext().getRequestDispatcher(this.getConfiguration().getLogOutPage());
        if (dispatch == null) {
            logger.samlSPCouldNotDispatchToLogoutPage(this.getConfiguration().getLogOutPage());
        } else {
            logger.trace("Forwarding request to logOutPage: " + this.getConfiguration().getLogOutPage());
            session.expire();
            try {
                dispatch.forward(request, response);
            } catch (Exception e) {
                // JBAS5.1 and 6 quirkiness
                dispatch.forward(request.getRequest(), response);
            }
        }
    }

    // Mock test purpose
    public void testStart() throws LifecycleException {
        this.saveRestoreRequest = false;
        if (context == null) {
            throw new RuntimeException("Catalina Context not set up");
        }
        startPicketLink();
    }

    protected void startPicketLink() throws LifecycleException {
        SystemPropertiesUtil.ensure();
        Handlers handlers = null;

        //Introduce a timer to reload configuration if desired
        if (timerInterval > 0) {
            if (timer == null) {
                timer = new Timer();
            }
            timer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    logger.info("Reloading configuration for " + context.getName());
                    processConfiguration();
                }
            }, timerInterval, timerInterval);
        }

        ServletContext servletContext = context.getServletContext();

        this.processConfiguration();

        new SessionManager(servletContext, new SessionManager.InitializationCallback() {
            @Override
            public void registerSessionListener(Class<? extends HttpSessionListener> listener) {
                context.addApplicationListener(listener.getName());
            }
        });
    }

    protected void stopPicketLink() {
        if (timer != null) {
            timer.cancel();
        }
    }

    /**
     * <p> Indicates if digital signatures/validation of SAML assertions are enabled. Subclasses that supports signature should
     * override this method. </p>
     *
     * @return
     */
    protected boolean doSupportSignature() {
        return getConfiguration().isSupportsSignature();
    }

    private Class<?> getAuthenticatorBaseClass() {
        Class<?> myClass = getClass();
        do {
            myClass = myClass.getSuperclass();
        } while (myClass != AuthenticatorBase.class);
        return myClass;
    }

    protected abstract void initKeyProvider(Context context) throws LifecycleException;

    public void setAuditHelper(PicketLinkAuditHelper auditHelper) {
        this.auditHelper = auditHelper;
    }
}
