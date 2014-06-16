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

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

/**
 * Implementation of the {@link javax.ws.rs.ext.MessageBodyReader} to deserialize
 * {@link org.picketlink.identity.federation.bindings.wildfly.rest.SAMLOauthInfo}
 *
 * @author Anil Saldhana
 * @since June 16, 2014
 */
@Provider
public class SAMLOauthInfoBodyReader implements MessageBodyReader<SAMLOauthInfo>{
    @Override
    public boolean isReadable(Class<?> aClass, Type type, Annotation[] annotations, MediaType mediaType) {
        if(MediaType.APPLICATION_JSON.equals(mediaType.toString())){
            return true;
        }
        return false;
    }

    @Override
    public SAMLOauthInfo readFrom(Class<SAMLOauthInfo> samlOauthInfoClass, Type type, Annotation[] annotations, MediaType mediaType,
                                  MultivaluedMap<String, String> stringStringMultivaluedMap, InputStream inputStream) throws IOException, WebApplicationException {
        if(MediaType.APPLICATION_JSON.equals(mediaType.toString())){
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(inputStream,SAMLOauthInfo.class);
        }
        return null;
    }
}