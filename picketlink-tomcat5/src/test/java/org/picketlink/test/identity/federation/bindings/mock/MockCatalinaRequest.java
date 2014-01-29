/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.test.identity.federation.bindings.mock;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.apache.catalina.Session;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

/**
 * Request for catalina container
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 20, 2009
 */
public class MockCatalinaRequest extends Request {
    private Map<String, String> params = new HashMap<String, String>();
    private Map<String, String> headers = new HashMap<String, String>();
    private Session session;
    private Principal principal;
    private String method;
    private String remotee;
    private String queryString;
    private String forwardPath;

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public void addHeader(String name, String value) {
        this.headers.put(name, value);
    }

    @Override
    public String getHeader(String name) {
        return headers.get(name);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    public Principal getUserPrincipal() {
        return principal;
    }

    @Override
    public void setUserPrincipal(Principal arg0) {
        this.principal = arg0;
    }

    @Override
    public String getParameter(String name) {
        return this.params.get(name);
    }

    public void setParameter(String key, String value) {
        params.put(key, value);
    }

    @Override
    public Enumeration getParameterNames() {
        return getEmptyEnumeration();
    }

    @Override
    public String getQueryString() {
        return this.queryString;
    }

    @Override
    public void setQueryString(String query) {
        this.queryString = query;
    }

    @Override
    public String getRequestURI() {
        return "";
    }

    @Override
    public void setAttribute(String name, Object value) {
        this.attributes.put(name,value);
    }

    @Override
    public String getRemoteAddr() {
        return this.remotee;
    }

    @Override
    public void setRemoteAddr(String remoteAddr) {
        this.remotee = remoteAddr;
    }

    @Override
    public String getMethod() {
        return this.method;
    }

    @Override
    public void setMethod(String method) {
        this.method = method;
    }

    @Override
    public Session getSessionInternal() {
        return session;
    }

    @Override
    public Session getSessionInternal(boolean b) {
        return session;
    }

    @Override
    public Connector getConnector() {
        try {
            return new Connector();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Enumeration getHeaderNames() {
        Vector vector = new Vector();
        vector.addAll(0, this.headers.keySet());
        return vector.elements();
    }

    @Override
    public Enumeration getHeaders(String name) {
        Vector vector = new Vector();
        vector.add(headers.get(name));
        return vector.elements();
    }

    @Override
    public Enumeration getLocales() {
        return getEmptyEnumeration();
    }

    @Override
    public String getDecodedRequestURI() {
        return "something";
    }

    @Override
    public Response getResponse() {
        return response;
    }

    public Cookie[] getCookies(){
        return this.cookies;
    }

    public void setSession(Session s) {
        this.session = s;
    }

    public HttpSession getSession(boolean b) {
        return this.session.getSession();
    }

    public HttpSession getSession() {
        return this.session.getSession();
    }

    public void clear() {
        this.params.clear();
        this.session = null;
    }

    public String getForwardPath() {
        return this.forwardPath;
    }

    public void setForwardPath(String path) {
        this.forwardPath = path;
    }

    private Enumeration getEmptyEnumeration(){
        Vector vector = new Vector();
        return vector.elements();
    }
}