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
package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An implementation of {@link io.undertow.security.api.AuthenticationMechanismFactory}
 * @author Anil Saldhana
 * @since December 17, 2013
 */
public class SPAuthenticationMechanismFactory implements AuthenticationMechanismFactory {
    protected ConcurrentHashMap<String,AuthenticationMechanism> map = new ConcurrentHashMap<String, AuthenticationMechanism>();

    @Override
    public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
        String theContextPath = properties.get(CONTEXT_PATH);
        SPFormAuthenticationMechanism am = get(theContextPath);
        if(am == null){
            am = new SPFormAuthenticationMechanism(mechanismName, properties.get(LOGIN_PAGE), properties.get(ERROR_PAGE));
            am.startPicketLink();
            map.put(theContextPath,am);
        }
        return am;
    }

    public SPFormAuthenticationMechanism get(String contextPath){
        return (SPFormAuthenticationMechanism) map.get(contextPath);
    }

    public void set(String contextPath, SPFormAuthenticationMechanism authenticationMechanism){
        map.put(contextPath, authenticationMechanism);
    }
}
