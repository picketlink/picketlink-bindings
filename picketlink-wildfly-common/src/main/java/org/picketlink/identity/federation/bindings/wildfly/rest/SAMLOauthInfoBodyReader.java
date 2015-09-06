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
