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
package org.picketlink.identity.federation.bindings.jetty.idp;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;

import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

/**
 * An implementation of {@link org.picketlink.identity.federation.core.interfaces.RoleGenerator}
 * for Jetty that peeks into the {@link javax.security.auth.Subject} available in the Jetty
 * identity
 * @author Anil Saldhana
 * @since December 09, 2013
 */
public class JettyRoleGenerator implements RoleGenerator{
    @Override
    public List<String> generateRoles(Principal principal) {
        List<String> roles = new ArrayList<String>();

        Request request = HttpChannel.getCurrentHttpChannel().getRequest();
        if(request != null){
            UserIdentity theIdentity = request.getResolvedUserIdentity();
            Subject theSubject = theIdentity.getSubject();

            //We assume that the principals other than the user principal represent roles
            Set<Principal> principalSet = theSubject.getPrincipals();
            if(!principalSet.isEmpty()){
                for(Principal aPrincipal: principalSet){
                    if(principal != aPrincipal){
                        roles.add(aPrincipal.getName());
                    }
                }
            }
        }
        return roles;
    }
}
