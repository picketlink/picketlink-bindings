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

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.coyote.ActionCode;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.MimeHeaders;
import org.picketlink.common.util.StringUtil;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PLINK-344: Account Chooser At the Service Provider to enable redirection to the appropriate IDP
 *
 * @author Anil Saldhana
 * @since January 21, 2014
 */
public abstract class AbstractAccountChooserValve extends ValveBase {
    public static final String ACCOUNT_CHOOSER_COOKIE_NAME = "picketlink.account.name";

    public static final String ACCOUNT_PARAMETER = "idp";

    protected String domainName;

    protected String accountHtml = "/accountChooser.html";

    protected ConcurrentHashMap<String, String> idpMap = new ConcurrentHashMap<String, String>();

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public void setIdentityProviderMap(String csv) {
        String[] keyValues = StringUtil.split(csv, ";");
        for (String keyValue : keyValues) {
            String[] idpPair = StringUtil.split(keyValue, "=");
            idpMap.put(idpPair[0], idpPair[1]);
        }
    }

    public void setAccountHtml(String html) {
        this.accountHtml = html;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        String cookieValue = cookieValue(request);
        if (cookieValue != null) {
            proceedToAuthentication(request, response, cookieValue);
        } else {
            String idpChosenKey = request.getParameter(ACCOUNT_PARAMETER);
            if (idpChosenKey != null) {
                String chosenIDP = idpMap.get(idpChosenKey);
                if (chosenIDP != null) {
                    request.setAttribute(BaseFormAuthenticator.DESIRED_IDP, chosenIDP);
                    proceedToAuthentication(request, response, idpChosenKey);
                }
            } else {
                // redirect to provided html
                saveRequest(request, request.getSessionInternal());
                Context context = (Context) getContainer();
                RequestDispatcher requestDispatcher = context.getServletContext().getRequestDispatcher(accountHtml);
                if(requestDispatcher != null){
                    requestDispatcher.forward(request,response);
                }
            }
        }
    }

    protected void proceedToAuthentication(Request request, Response response, String cookieValue) throws IOException,
            ServletException {
        try {
            getNext().invoke(request, response);
        } finally {
            // Send back a cookie
            Cookie cookie = new Cookie(ACCOUNT_CHOOSER_COOKIE_NAME, cookieValue);
            cookie.setDomain(domainName);
            cookie.setMaxAge(-1);
            response.addCookie(cookie);
        }
    }

    protected String cookieValue(Request request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getDomain().equalsIgnoreCase(domainName)) {
                    // Found a cookie with the same domain name
                    String cookieName = cookie.getName();
                    if (ACCOUNT_CHOOSER_COOKIE_NAME.equals(cookieName)) {
                        // Found cookie
                        String cookieValue = cookie.getValue();
                        String chosenIDP = idpMap.get(cookieValue);
                        if (chosenIDP != null) {
                            request.setAttribute(BaseFormAuthenticator.DESIRED_IDP, chosenIDP);
                            return cookieValue;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Save the original request information into our session.
     *
     * @param request The request to be saved
     * @param session The session to contain the saved information
     * @throws IOException
     */
    protected abstract void saveRequest(Request request, Session session) throws IOException;

    /**
     * Restore the original request from information stored in our session. If the original request is no longer present
     * (because the session timed out), return <code>false</code>; otherwise, return <code>true</code>.
     *
     * @param request The request to be restored
     * @param session The session containing the saved information
     */
    protected abstract boolean restoreRequest(Request request, Session session) throws IOException;
}