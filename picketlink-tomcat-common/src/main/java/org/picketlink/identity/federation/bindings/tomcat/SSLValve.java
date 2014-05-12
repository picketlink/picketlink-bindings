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
package org.picketlink.identity.federation.bindings.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;

import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Valve to fill the SSL information in the request mod_header is used to fill the headers and the valve will fill the parameters of
 * the request. In httpd.conf add the following:
 *
 * <IfModule ssl_module> RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s" RequestHeader set SSL_CIPHER "%{SSL_CIPHER}s"
 * RequestHeader set SSL_SESSION_ID "%{SSL_SESSION_ID}s" RequestHeader set SSL_CIPHER_USEKEYSIZE "%{SSL_CIPHER_USEKEYSIZE}s"
 * </IfModule>
 *
 * Visit: https://community.jboss.org/wiki/SSLModproxyForwarding
 *
 * @author Jean-Frederic Clere
 * @author Anil Saldhana
 * @since November 07, 2013
 */
public class SSLValve extends ValveBase {

    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        // mod_header converts the '\n' into ' ' so we have to rebuild the client certificate
        String strcert0 = request.getHeader("ssl_client_cert");

        if (isNotNull(strcert0)) {

            String strcert1 = strcert0.replace(' ', '\n');
            String strcert2 = strcert1.substring(28, strcert1.length() - 26);
            String strcert3 = new String("-----BEGIN CERTIFICATE-----\n");
            String strcert4 = strcert3.concat(strcert2);
            String strcerts = strcert4.concat("\n-----END CERTIFICATE-----\n");

            // ByteArrayInputStream bais = new ByteArrayInputStream(strcerts.getBytes("UTF-8"));
            ByteArrayInputStream bais = new ByteArrayInputStream(strcerts.getBytes());
            X509Certificate[] jsseCerts = null;
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
                jsseCerts = new X509Certificate[1];
                jsseCerts[0] = cert;
            } catch (CertificateException certificateException) {
                logger.error("SSLValve failed :" + strcerts);
                logger.error(certificateException);
            }
            request.setAttribute("javax.servlet.request.X509Certificate", jsseCerts);
        }
        strcert0 = request.getHeader("ssl_cipher");
        if (isNotNull(strcert0)) {
            request.setAttribute("javax.servlet.request.cipher_suite", strcert0);
        }
        strcert0 = request.getHeader("ssl_session_id");
        if (isNotNull(strcert0)) {
            request.setAttribute("javax.servlet.request.ssl_session", strcert0);
        }
        strcert0 = request.getHeader("ssl_cipher_usekeysize");
        if (isNotNull(strcert0)) {
            request.setAttribute("javax.servlet.request.key_size", strcert0);
        }
        getNext().invoke(request, response);
    }

    private boolean isNotNull(String str) {
        return str != null && !"".equals(str.trim());
    }
}