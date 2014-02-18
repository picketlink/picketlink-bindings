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
package org.picketlink.identity.federation.bindings.jboss.auth;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.util.StringUtil;

/**
 * PLINK-359: Login Module that extracts user name from the principal based on a regular expression
 * @author Anil Saldhana
 * @since February 10, 2014
 */
public class RegExUserNameLoginModule extends UsernamePasswordLoginModule {
    private static final String REGEX_MODULE_OPTION = "regex";

    /** The login identity */
    private Principal identity;
    /** The proof of login identity */
    private char[] credential;

    private Pattern pattern;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.addValidOptions(new String[] {REGEX_MODULE_OPTION});
        super.initialize(subject, callbackHandler, sharedState, options);

        //The format is in the options
        String regex = (String) options.get(REGEX_MODULE_OPTION);
        if(regex == null){
            log.error("regex module option not found");
        }
        pattern = Pattern.compile(regex);
    }

    @Override
    public boolean login() throws LoginException {
        // Setup our view of the user
        Object username = sharedState.get("javax.security.auth.login.name");

        if(username == null){
            throw new LoginException(ErrorCodes.NULL_ARGUMENT  + ": No username");
        }

        if( username instanceof Principal){
            identity = (Principal) username;

            String extractedUserName = extractUserName(identity.getName());
            try{
                identity = createIdentity(extractedUserName);
            }
            catch(Exception e){
                log.debug("Failed to create principal", e);
            }
        }
        else
        {
            String name = username.toString();

            name = extractUserName(name);
            try{
                identity = createIdentity(name);
            }
            catch(Exception e){
                log.debug("Failed to create principal", e);
                throw new LoginException(ErrorCodes.PROCESSING_EXCEPTION + "Failed to create principal: "+ e.getMessage());
            }
        }
        Object password = sharedState.get("javax.security.auth.login.password");
        if( password instanceof char[] ){
            credential = (char[]) password;
        }
        else if( password != null ) {
            String tmp = password.toString();
            credential = tmp.toCharArray();
        }
        // Add the principal and password to the shared state map
        sharedState.put("javax.security.auth.login.name", identity);
        sharedState.put("javax.security.auth.login.password", credential);

        return true;
    }

    @Override
    protected String getUsersPassword() throws LoginException {
        return null;
    }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        return new Group[0];
    }

    protected String extractUserName(String theName) {
        Matcher matcher = pattern.matcher(theName);

        if (matcher.find() && matcher.groupCount() > 0) {
            return matcher.group(1);
        }
        return theName;
    }
}