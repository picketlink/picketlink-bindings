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