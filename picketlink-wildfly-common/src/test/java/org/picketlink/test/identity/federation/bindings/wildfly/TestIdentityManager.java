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
package org.picketlink.test.identity.federation.bindings.wildfly;

import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import org.picketlink.identity.federation.bindings.wildfly.idp.PicketLinkUndertowPrincipal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Simple Identity Manager that deals with (user1,password1,role1) combination
 * @author Anil Saldhana
 * @since December 02, 2013
 */
public class TestIdentityManager implements IdentityManager {
    private String userName,password,role;

    public void addUser(String userName, String password, String role){
        this.userName = userName;
        this.password = password;
        this.role = role;
    }
    @Override
    public Account verify(Account account) {
        return account;
    }

    @Override
    public Account verify(String userName, Credential credential) {
        PasswordCredential pwd = (PasswordCredential) credential;
        String pw = new String(pwd.getPassword());

        if(userName.equals("user1") && pw.equals("password1")){
            final List<String> theRoles = new ArrayList<String>();
            theRoles.add("role1");

            return new Account() {
                @Override
                public Principal getPrincipal() {
                    return new PicketLinkUndertowPrincipal("user1",theRoles);
                }

                @Override
                public Set<String> getRoles() {
                    return new HashSet<String>(theRoles);
                }
            };
        }else {
            return null;
        }
    }

    @Override
    public Account verify(Credential credential) {
        throw new RuntimeException();
    }
}