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
package org.picketlink.social.openid;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.List;

/**
 * A {@link javax.security.auth.spi.LoginModule} for JBoss environment to support OpenID
 *
 * @author Anil Saldhana
 * @since May 19, 2011
 */
public class OpenIDLoginModule extends UsernamePasswordLoginModule {

    @Override
    protected Principal getIdentity() {
        return OpenIDProcessor.cachedPrincipal.get();
    }

    @Override
    protected String getUsersPassword() throws LoginException {
        return OpenIDProcessor.EMPTY_PASSWORD;
    }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group group = new SimpleGroup("Roles");

        List<String> roles = OpenIDProcessor.cachedRoles.get();

        if (roles != null) {
            for (String role : roles) {
                group.addMember(new SimplePrincipal(role));
            }
        }
        return new Group[]{group};
    }
}