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

import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

/**
 * PLINK-344: Account Chooser At the Service Provider to enable redirection to the appropriate IDP Implementation for Apache Tomcat
 * 5
 *
 * @author Anil Saldhana
 * @since January 22, 2014
 */
public class AccountChooserValve extends AbstractAccountChooserValve {

    /**
     * Save the original request information into our session.
     *
     * Implementation from
     * http://svn.apache.org/repos/asf/tomcat/archive/tc5.5.x/tags/TOMCAT_5_5_9/container/catalina/src/share/
     * org/apache/catalina/authenticator/FormAuthenticator.java
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
            for (int i = 0; i < cookies.length; i++)
                saved.addCookie(cookies[i]);
        }
        Enumeration names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            Enumeration values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                String value = (String) values.nextElement();
                saved.addHeader(name, value);
            }
        }
        Enumeration locales = request.getLocales();
        while (locales.hasMoreElements()) {
            Locale locale = (Locale) locales.nextElement();
            saved.addLocale(locale);
        }
        Map parameters = request.getParameterMap();
        Iterator paramNames = parameters.keySet().iterator();
        while (paramNames.hasNext()) {
            String paramName = (String) paramNames.next();
            String[] paramValues = (String[]) parameters.get(paramName);
            saved.addParameter(paramName, paramValues);
        }
        saved.setMethod(request.getMethod());
        saved.setQueryString(request.getQueryString());
        saved.setRequestURI(request.getRequestURI());

        // Stash the SavedRequest in our session for later use
        session.setNote(Constants.FORM_REQUEST_NOTE, saved);
    }

    /**
     * Restore the original request from information stored in our session. If the original request is no longer present
     * (because the session timed out), return <code>false</code>; otherwise, return <code>true</code>.
     *
     * Implementation from
     * http://svn.apache.org/repos/asf/tomcat/archive/tc5.5.x/tags/TOMCAT_5_5_9/container/catalina/src/share/
     * org/apache/catalina/authenticator/FormAuthenticator.java
     *
     * @param request The request to be restored
     * @param session The session containing the saved information
     */
    protected boolean restoreRequest(Request request, Session session) throws IOException {
        // Retrieve and remove the SavedRequest object from our session
        SavedRequest saved = (SavedRequest) session.getNote(Constants.FORM_REQUEST_NOTE);
        session.removeNote(Constants.FORM_REQUEST_NOTE);
        session.removeNote(Constants.FORM_PRINCIPAL_NOTE);
        if (saved == null)
            return (false);

        // Modify our current request to reflect the original one
        request.clearCookies();
        Iterator cookies = saved.getCookies();
        while (cookies.hasNext()) {
            request.addCookie((Cookie) cookies.next());
        }
        request.clearHeaders();
        Iterator names = saved.getHeaderNames();
        while (names.hasNext()) {
            String name = (String) names.next();
            Iterator values = saved.getHeaderValues(name);
            while (values.hasNext()) {
                request.addHeader(name, (String) values.next());
            }
        }
        request.clearLocales();
        Iterator locales = saved.getLocales();
        while (locales.hasNext()) {
            request.addLocale((Locale) locales.next());
        }
        request.clearParameters();
        if ("POST".equalsIgnoreCase(saved.getMethod())) {
            Iterator paramNames = saved.getParameterNames();
            while (paramNames.hasNext()) {
                String paramName = (String) paramNames.next();
                String[] paramValues = saved.getParameterValues(paramName);
                request.addParameter(paramName, paramValues);
            }
        }
        request.setMethod(saved.getMethod());
        request.setQueryString(saved.getQueryString());
        request.setRequestURI(saved.getRequestURI());
        return (true);
    }
}
