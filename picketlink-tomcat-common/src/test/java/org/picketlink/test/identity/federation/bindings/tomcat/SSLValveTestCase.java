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
package org.picketlink.test.identity.federation.bindings.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.picketlink.identity.federation.bindings.tomcat.SSLValve;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import static org.mockito.Mockito.*;

/**
 * Unit Test the {@link SSLValve}
 * @author Anil Saldhana
 * @since November 11, 2013
 */
public class SSLValveTestCase {
    private Map<String,Object> map = new HashMap<String, Object>();

    /**
     * Test that the {@link SSLValve} puts the {@link X509Certificate}
     * in the {@link javax.servlet.http.HttpServletRequest} attribute
     * at javax.servlet.request.X509Certificate
     * @throws Exception
     */
    @Test
    public void testSSLValvePutsCertificateInRequestAttribute() throws Exception{
        SSLValve valve = new SSLValve();
        valve.setNext(new ValidatorValve());

        Request mockRequest = mock(Request.class);
        Response mockResponse = mock(Response.class);

        //When there is a setAttribute call on the request, send it to our map
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                map.put((String) args[0],args[1]);
                return null;
            }
        }).when(mockRequest).setAttribute(Mockito.anyString(), Mockito.anyObject());


        //When there is a getAttribute call on the request, send it our map
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                return map.get(args[0]);
            }
        }).when(mockRequest).getAttribute(Mockito.anyString());

        //When SSLValve asks the request for the header, provide it a certificate string
        when(mockRequest.getHeader("ssl_client_cert")).thenReturn(getSSLClientCert());

        valve.invoke(mockRequest, mockResponse);
    }

    private String getSSLClientCert() throws Exception{
        InputStream bis = getClass().getClassLoader().getResourceAsStream("certs/servercert.txt");
        return new Scanner(bis).useDelimiter("\\Z").next();
    }

    private X509Certificate getTestingCertificate(String fromTextFile) {
        // Certificate
        InputStream bis = getClass().getClassLoader().getResourceAsStream("certs/" + fromTextFile);
        X509Certificate cert = null;

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(bis);
        } catch (Exception e) {
            throw new IllegalStateException("Could not load testing certificate.", e);
        } finally {
            if (bis != null) {
                try {
                    bis.close();
                } catch (IOException e) {
                }
            }
        }
        return cert;
    }

    public class ValidatorValve extends ValveBase{

        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            //Let us validate the request
            X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
            if(certs == null){
                throw new RuntimeException("Certs are null");
            }else {
                System.out.println("We found certificate");
            }
        }
    }
}