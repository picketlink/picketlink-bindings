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
package org.picketlink.identity.federation.bindings.wildfly.rest;

import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.io.StringWriter;

/**
 * Data Transfer Object
 * @author Anil Saldhana
 * @since April 30, 2014
 */
public class SAMLOauthInfo {
    private String samlAssertionID, oauthToken;

    public SAMLOauthInfo(){
    }

    public SAMLOauthInfo(String samlAssertionID, String oauthToken) {
        this.samlAssertionID = samlAssertionID;
        this.oauthToken = oauthToken;
    }

    public void setSamlAssertionID(String samlAssertionID) {
        this.samlAssertionID = samlAssertionID;
    }

    public void setOauthToken(String oauthToken) {
        this.oauthToken = oauthToken;
    }

    public String getOauthToken() {
        return oauthToken;
    }

    public String getSamlAssertionID() {

        return samlAssertionID;
    }

    public String asJSON(){
        StringWriter stringWriter = new StringWriter();

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            objectMapper.writeValue(stringWriter,this);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return stringWriter.toString();
    }
}