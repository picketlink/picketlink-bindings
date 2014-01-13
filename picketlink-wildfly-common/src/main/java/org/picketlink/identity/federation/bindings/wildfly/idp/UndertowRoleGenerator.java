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

import org.jboss.security.SecurityContextAssociation;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

import javax.security.auth.Subject;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

/**
 * Implementation of {@link org.picketlink.identity.federation.core.interfaces.RoleGenerator} for Undertow
 *
 * @author Anil Saldhana
 * @since December 06, 2013
 */
public class UndertowRoleGenerator implements RoleGenerator {

    @Override
    public List<String> generateRoles(Principal principal) {
        if (principal instanceof PicketLinkUndertowPrincipal) {
            PicketLinkUndertowPrincipal pup = (PicketLinkUndertowPrincipal) principal;
            return Collections.unmodifiableList(pup.getRoles());
        } else {
            return fromSubject();
        }
    }

    /**
     * <p>This method tries to load roles from the authenticated {@link javax.security.auth.Subject} obtained from
     * {@link org.jboss.security.SecurityContextAssociation}.</p>
     *
     * <p>This method is particularly useful when the application is deployed in WildFly and the authentication is performed by
     * a specific security domain (JAAS).</p>
     *
     * <p>Outside WildFly ecosystem, this method won't work as it relies on the security extension to get the subject.</p>
     *
     * @return
     */
    private List<String> fromSubject() {
        List roles = new ArrayList();
        Subject subject = SecurityContextAssociation.getSubject();

        if (subject != null) {
            Set<Group> groups = subject.getPrincipals(Group.class);

            if (groups != null) {
                for (Group group : groups) {
                    if ("Roles".equals(group.getName())) {
                        Enumeration<? extends Principal> subjectRoles = group.members();
                        while (subjectRoles.hasMoreElements()) {
                            Principal role = subjectRoles.nextElement();
                            roles.add(role.getName());
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableList(roles);
    }
}