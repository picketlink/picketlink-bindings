package org.picketlink.identity.federation.bindings.wildfly.idp;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.FilterInfo;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.web.filters.IDPFilter;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;

import javax.servlet.DispatcherType;
import javax.servlet.ServletContext;
import java.util.Map;

import static org.picketlink.common.constants.GeneralConstants.AUDIT_HELPER;
import static org.picketlink.common.constants.GeneralConstants.CONFIG_PROVIDER;

/**
 * An implementation of {@link ServletExtension} that can turn a deployment
 * into an IDP
 *
 * @author Anil Saldhana
 * @since November 25, 2013
 */
public class IDPServletExtension implements ServletExtension{

    private final SAMLConfigurationProvider configurationProvider;
    private final PicketLinkAuditHelper auditHelper;

    public IDPServletExtension(SAMLConfigurationProvider configurationProvider, PicketLinkAuditHelper auditHelper) {
        this.configurationProvider = configurationProvider;
        this.auditHelper = auditHelper;
    }

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        if (!hasFilter(deploymentInfo)) {
            configureFilter(deploymentInfo);
        }

        // we set the config provider and audit helper to the application scope so we can retrive them from the filter during the initialization
        servletContext.setAttribute(CONFIG_PROVIDER, this.configurationProvider);
        servletContext.setAttribute(AUDIT_HELPER, this.auditHelper);
    }

    private void configureFilter(DeploymentInfo deploymentInfo) {
        String filterName = IDPFilter.class.getSimpleName();

        deploymentInfo.addFilter(new FilterInfo(filterName, IDPFilter.class));
        deploymentInfo.addFilterUrlMapping(filterName, "/*", DispatcherType.REQUEST);
    }

    private boolean hasFilter(DeploymentInfo deploymentInfo) {
        Map<String, FilterInfo> filters = deploymentInfo.getFilters();

        for (FilterInfo filterInfo : filters.values()) {
            if (IDPFilter.class.isAssignableFrom(filterInfo.getFilterClass())) {
                return true;
            }
        }

        return false;
    }
}
