package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static org.picketlink.common.constants.GeneralConstants.AUDIT_HELPER;
import static org.picketlink.common.constants.GeneralConstants.CONFIG_PROVIDER;

/**
 *
 * <p>{@link io.undertow.servlet.ServletExtension} that enables the SAML authentication mechanism for service provider deployments.</p>
 *
 * <p>In order to get the extension properly configured, deployments must provide a <code>META-INF/services//META-INF/services/io.undertow.servlet.ServletExtension</code>
 * file in <code>WEB-INF/classes</code>.</p>
 *
 * @author Pedro Igor
 */
public class SPServletExtension implements ServletExtension {

    private final SAMLConfigurationProvider configurationProvider;
    private final PicketLinkAuditHelper auditHelper;

    public SPServletExtension(SAMLConfigurationProvider configurationProvider, PicketLinkAuditHelper auditHelper) {
        this.configurationProvider = configurationProvider;
        this.auditHelper = auditHelper;
    }

    public SPServletExtension() {
        this(null, null);
    }

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, final ServletContext servletContext) {
        deploymentInfo.addAuthenticationMechanism(HttpServletRequest.FORM_AUTH, new AuthenticationMechanismFactory() {
            @Override
            public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
                SPFormAuthenticationMechanism authenticationMechanism = new SPFormAuthenticationMechanism(formParserFactory, mechanismName, properties
                    .get(LOGIN_PAGE), properties.get(ERROR_PAGE), servletContext, getConfigurationProvider(servletContext), getAuditHelper(servletContext));

                return authenticationMechanism;
            }
        });
    }

    private SAMLConfigurationProvider getConfigurationProvider(ServletContext servletContext) {
        String configProviderType = servletContext.getInitParameter(CONFIG_PROVIDER);

        if (configProviderType != null) {
            try {
                return (SAMLConfigurationProvider) SecurityActions
                    .loadClass(Thread.currentThread().getContextClassLoader(), configProviderType).newInstance();
            } catch (Exception e) {
                throw new RuntimeException("Could not create config provider [" + configProviderType + "].", e);
            }
        }

        return this.configurationProvider;
    }

    private PicketLinkAuditHelper getAuditHelper(ServletContext servletContext) {
        String auditHelperType = servletContext.getInitParameter(AUDIT_HELPER);

        if (auditHelperType != null) {
            try {
                return (PicketLinkAuditHelper) SecurityActions
                    .loadClass(Thread.currentThread().getContextClassLoader(), auditHelperType).newInstance();
            } catch (Exception e) {
                throw new RuntimeException("Could not create audit helper [" + auditHelperType + "].", e);
            }
        }

        return this.auditHelper;
    }
}
