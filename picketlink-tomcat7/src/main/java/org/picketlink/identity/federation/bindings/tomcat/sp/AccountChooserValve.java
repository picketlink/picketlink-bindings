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
package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.coyote.ActionCode;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.MimeHeaders;

import javax.servlet.http.Cookie;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;

/**
 * PLINK-344: Account Chooser At the Service Provider to enable redirection to the appropriate IDP Implementation for Apache Tomcat
 * 7
 *
 * @author Anil Saldhana
 * @since January 22, 2014
 */
public class AccountChooserValve extends AbstractAccountChooserValve {

    /**
     * Save the original request information into our session.
     *
     * Implementation from
     * http://svn.apache.org/repos/asf/tomcat/tc7.0.x/tags/TOMCAT_7_0_50/java/org/apache/catalina/authenticator
     * /FormAuthenticator.java
     *
     * @param request The request to be saved
     * @param session The session to contain the saved information
     * @throws java.io.IOException
     */
    protected void saveRequest(Request request, Session session) throws IOException {
        // Create and populate a SavedRequest object for this request
        SavedRequest saved = new SavedRequest();
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                saved.addCookie(cookies[i]);
            }
        }
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            Enumeration<String> values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                String value = values.nextElement();
                saved.addHeader(name, value);
            }
        }
        Enumeration<Locale> locales = request.getLocales();
        while (locales.hasMoreElements()) {
            Locale locale = locales.nextElement();
            saved.addLocale(locale);
        }

        // May need to acknowledge a 100-continue expectation
        request.getResponse().sendAcknowledgement();

        ByteChunk body = new ByteChunk();
        body.setLimit(request.getConnector().getMaxSavePostSize());

        byte[] buffer = new byte[4096];
        int bytesRead;
        InputStream is = request.getInputStream();

        while ((bytesRead = is.read(buffer)) >= 0) {
            body.append(buffer, 0, bytesRead);
        }

        // Only save the request body if there is something to save
        if (body.getLength() > 0) {
            saved.setContentType(request.getContentType());
            saved.setBody(body);
        }

        saved.setMethod(request.getMethod());
        saved.setQueryString(request.getQueryString());
        saved.setRequestURI(request.getRequestURI());
        saved.setDecodedRequestURI(request.getDecodedRequestURI());

        // Stash the SavedRequest in our session for later use
        session.setNote(Constants.FORM_REQUEST_NOTE, saved);
    }

    /**
     * Restore the original request from information stored in our session. If the original request is no longer present
     * (because the session timed out), return <code>false</code>; otherwise, return <code>true</code>.
     *
     * Implementation from
     * http://svn.apache.org/repos/asf/tomcat/tc7.0.x/tags/TOMCAT_7_0_50/java/org/apache/catalina/authenticator
     * /FormAuthenticator.java
     *
     * @param request The request to be restored
     * @param session The session containing the saved information
     */
    protected boolean restoreRequest(Request request, Session session) throws IOException {
        // Retrieve and remove the SavedRequest object from our session
        SavedRequest saved = (SavedRequest) session.getNote(Constants.FORM_REQUEST_NOTE);
        session.removeNote(Constants.FORM_REQUEST_NOTE);
        session.removeNote(Constants.FORM_PRINCIPAL_NOTE);
        if (saved == null) {
            return (false);
        }

        // Swallow any request body since we will be replacing it
        // Need to do this before headers are restored as AJP connector uses
        // content length header to determine how much data needs to be read for
        // request body
        byte[] buffer = new byte[4096];
        InputStream is = request.createInputStream();
        while (is.read(buffer) >= 0) {
            // Ignore request body
        }

        // Modify our current request to reflect the original one
        request.clearCookies();
        Iterator<Cookie> cookies = saved.getCookies();
        while (cookies.hasNext()) {
            request.addCookie(cookies.next());
        }

        String method = saved.getMethod();
        MimeHeaders rmh = request.getCoyoteRequest().getMimeHeaders();
        rmh.recycle();
        boolean cachable = "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
        Iterator<String> names = saved.getHeaderNames();
        while (names.hasNext()) {
            String name = names.next();
            // The browser isn't expecting this conditional response now.
            // Assuming that it can quietly recover from an unexpected 412.
            // BZ 43687
            if (!("If-Modified-Since".equalsIgnoreCase(name) || (cachable && "If-None-Match".equalsIgnoreCase(name)))) {
                Iterator<String> values = saved.getHeaderValues(name);
                while (values.hasNext()) {
                    rmh.addValue(name).setString(values.next());
                }
            }
        }

        request.clearLocales();
        Iterator<Locale> locales = saved.getLocales();
        while (locales.hasNext()) {
            request.addLocale(locales.next());
        }

        request.getCoyoteRequest().getParameters().recycle();
        request.getCoyoteRequest().getParameters().setQueryStringEncoding(request.getConnector().getURIEncoding());

        ByteChunk body = saved.getBody();

        if (body != null) {
            request.getCoyoteRequest().action(ActionCode.REQ_SET_BODY_REPLAY, body);

            // Set content type
            MessageBytes contentType = MessageBytes.newInstance();

            // If no content type specified, use default for POST
            String savedContentType = saved.getContentType();
            if (savedContentType == null && "POST".equalsIgnoreCase(method)) {
                savedContentType = "application/x-www-form-urlencoded";
            }

            contentType.setString(savedContentType);
            request.getCoyoteRequest().setContentType(contentType);
        }

        request.getCoyoteRequest().method().setString(method);

        request.getCoyoteRequest().queryString().setString(saved.getQueryString());

        request.getCoyoteRequest().requestURI().setString(saved.getRequestURI());
        return (true);
    }
}
