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
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of {@link java.security.Principal} that stores the current principal
 * name and a {@link java.util.List} of roles
 *
 * @author Anil Saldhana
 * @since December 19, 2013
 */
public class PicketLinkUndertowPrincipal implements Principal,Serializable {
    private static final long serialVersionUID = 5333209596084739156L;

    protected PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    protected String name = null;

    protected List<String> roles = new ArrayList<String>();


    public PicketLinkUndertowPrincipal(String name, List<String> roles) {
        this.name = name;
        if (roles == null) {
            throw logger.nullArgumentError("roles");
        }
        this.roles.addAll(roles);
    }

    @Override
    public String getName() {
        return name;
    }

    public List<String> getRoles(){
        return Collections.unmodifiableList(roles);
    }
}