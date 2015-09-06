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
