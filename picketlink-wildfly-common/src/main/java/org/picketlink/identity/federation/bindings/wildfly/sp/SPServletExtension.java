/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
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
                    .get(LOGIN_PAGE), properties.get(ERROR_PAGE), servletContext, configurationProvider, auditHelper);

                return authenticationMechanism;
            }
        });
    }
}
