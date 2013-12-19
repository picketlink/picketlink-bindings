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

import io.undertow.security.idm.Account;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of {@link org.picketlink.identity.federation.core.interfaces.RoleGenerator}
 * for Undertow
 * @author Anil Saldhana
 * @since December 06, 2013
 */
public class UndertowRoleGenerator implements RoleGenerator {
    protected List<String> roles = new ArrayList<String>();
    @Override
    public List<String> generateRoles(Principal principal) {
        if(principal instanceof PicketLinkUndertowPrincipal){
            PicketLinkUndertowPrincipal pup = (PicketLinkUndertowPrincipal) principal;
            return pup.getRoles();
        }
        return roles;
    }
}