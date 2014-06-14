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
package org.picketlink.identity.federation.bindings.jboss.roles;

import org.apache.catalina.connector.Request;
import org.jboss.security.SimplePrincipal;
import org.picketlink.identity.federation.bindings.tomcat.TomcatRoleGenerator;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.List;

/**
 * {@link org.picketlink.identity.federation.core.interfaces.RoleGenerator} for JBossWeb
 *
 * @author Anil Saldhana
 * @since February 21, 2014
 */
public class JBossWebRoleGenerator extends TomcatRoleGenerator {

    @Override
    public List<String> generateRoles(Principal principal) {
        if (principal instanceof SimplePrincipal) {
            //Use JACC to get the request
            try {
                HttpServletRequest request =
                    (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
                if (request instanceof Request) {
                    Request catalinaRequest = (Request) request;
                    return super.generateRoles(catalinaRequest.getPrincipal());
                }
            } catch (PolicyContextException e) {
                throw new RuntimeException(e);
            }
        } else {
            return super.generateRoles(principal);
        }
        return null;
    }
}