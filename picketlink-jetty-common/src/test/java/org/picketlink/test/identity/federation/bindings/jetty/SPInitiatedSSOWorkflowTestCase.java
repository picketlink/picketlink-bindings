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
package org.picketlink.test.identity.federation.bindings.jetty;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.SubmitButton;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Password;
import org.eclipse.jetty.webapp.WebAppContext;
import org.junit.Before;
import org.junit.Test;
import org.picketlink.identity.federation.bindings.jetty.sp.SPFormAuthenticator;
import org.picketlink.identity.federation.web.filters.IDPFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.security.Principal;

import static org.junit.Assert.assertTrue;

/**
 * Unit Test for SP Initiated SSO Workflow
 * @author Anil Saldhana
 * @since December 09, 2013
 */
public class SPInitiatedSSOWorkflowTestCase {

    protected WebAppContext idpContext = null;
    protected WebAppContext spContext = null;

    protected Server server = null;
    private WebConversation webConversation = null;
    private WebResponse webResponse = null;
    private int responseCode = 0;

    @Before
    public void setup() throws Exception {
        server = new Server(8080);

        deployIDP();
        deploySP();

        HandlerCollection handlers = new HandlerCollection();
        handlers.setHandlers(new Handler[] { idpContext, spContext });
        server.setHandler(handlers);

        server.start();
    }


    @Test
    public void testSSO() throws Exception {
        String spURI = "http://localhost:8080/sp/secured/test";
        WebRequest serviceRequest1 = new GetMethodWebRequest(spURI);
        webConversation = new WebConversation();
        HttpUnitOptions.setLoggingHttpHeaders(true);

        webResponse = webConversation.getResponse(serviceRequest1);

        responseCode = webResponse.getResponseCode();
        if (responseCode == HttpServletResponse.SC_SEE_OTHER) {
            String otherLocation = webResponse.getHeaderField("LOCATION");
            webResponse = webConversation.getResponse(otherLocation);
        }
        WebForm loginForm = webResponse.getForms()[0];
        loginForm.setParameter("j_username", "user1");
        loginForm.setParameter("j_password", "password1");
        SubmitButton submitButton = loginForm.getSubmitButtons()[0];
        submitButton.click();

        webResponse = webConversation.getCurrentPage();
        responseCode = webResponse.getResponseCode();
        while (responseCode == 303) {
            handle303();
        }
        String text = webResponse.getText();
        assertTrue(" Saw user1 ", text.contains("user1"));
    }

    protected void deployIDP() throws Exception {
        idpContext = new WebAppContext();
        idpContext.setResourceBase(getClass().getClassLoader().getResource("idp").toExternalForm());
        idpContext.setParentLoaderPriority(true);
        idpContext.setContextPath("/idp");

        idpContext.addServlet(new ServletHolder(new SendUsernameServlet()), "/*");
        idpContext.addServlet(new ServletHolder(new FormLoginServlet()), "/FormLoginServlet");
        idpContext.addFilter(IDPFilter.class.getName(), "/*", null);

        ConstraintSecurityHandler securityHandler = formHandler();
        FormAuthenticator authenticator = new FormAuthenticator("/FormLoginServlet", "/error.html", false);
        securityHandler.setAuthenticator(authenticator);

        idpContext.setSecurityHandler(securityHandler);
    }

    protected void deploySP() throws Exception {
        spContext = new WebAppContext();
        spContext.setResourceBase(getClass().getClassLoader().getResource("sp").toExternalForm());
        spContext.setContextPath("/sp");
        spContext.setParentLoaderPriority(true);

        spContext.addServlet(new ServletHolder(new SendUsernameServlet()), "/secured/*");

        spContext.addServlet(new ServletHolder(new FormLoginServlet()), "/FormLoginServlet");

        ConstraintSecurityHandler securityHandler = formHandler();

        SPFormAuthenticator authenticator = new SPFormAuthenticator("/FormLoginServlet", "/error.html", false);
        securityHandler.setAuthenticator(authenticator);

        spContext.setSecurityHandler(securityHandler);
    }

    private ConstraintSecurityHandler formHandler() {
        Constraint constraint = new Constraint();
        constraint.setName(Constraint.__FORM_AUTH);
        ;
        constraint.setRoles(new String[] { "role1" });
        constraint.setAuthenticate(true);

        ConstraintMapping constraintMapping = new ConstraintMapping();
        constraintMapping.setConstraint(constraint);
        constraintMapping.setPathSpec("/*");

        ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
        securityHandler.setConstraintMappings(new ConstraintMapping[] { constraintMapping });

        HashLoginService loginService = new HashLoginService();
        loginService.putUser("user1", new Password("password1"), new String[] { "role1" });
        securityHandler.setLoginService(loginService);
        return securityHandler;
    }

    /*
     * @author Stuart Douglas
     */
    public static class FormLoginServlet extends HttpServlet {

        @Override
        protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
            Writer writer = resp.getWriter();
            writer.write("Login Page");
            writer.write("<form id=\"login_form\" name=\"login_form\" method=\"post\"\n"
                    + "         action=\"j_security_check\" enctype=\"application/x-www-form-urlencoded\">\n"
                    + "         <div style=\"margin-left: 15px;\">\n"
                    + "                <p>\n"
                    + "                      <label for=\"username\"> Username</label><br /> <input id=\"username\"\n"
                    + "                                type=\"text\" name=\"j_username\" size=\"20\" />\n"
                    + "                </p>\n"
                    + "                <p>\n"
                    + "                       <label for=\"password\"> Password</label><br /> <input id=\"password\"\n"
                    + "                               type=\"password\" name=\"j_password\" value=\"\" size=\"20\" />\n"
                    + "                </p>\n"
                    + "                <center>\n"
                    + "                       <input id=\"submit\" type=\"submit\" name=\"submit\" value=\"Login\"\n"
                    + "                                class=\"buttonmed\" />\n"
                    + "                 </center>\n"
                    + "         </div>\n"
                    + "   </form>");

        }
    }

    /**
     * @author Stuart Douglas
     */
    public static class SendUsernameServlet extends HttpServlet {
        @Override
        protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
            OutputStream stream = resp.getOutputStream();
            Principal principal = req.getUserPrincipal();
            String name = principal.getName();
            stream.write(name.getBytes());
        }

        @Override
        protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
                IOException {
            OutputStream stream = resp.getOutputStream();
            Principal principal = req.getUserPrincipal();
            String name = principal.getName();
            stream.write(name.getBytes());
        }
    }

    private void handle303() throws Exception {
        String otherLocation = webResponse.getHeaderField("LOCATION");
        webResponse = webConversation.getResponse(otherLocation);
        responseCode = webResponse.getResponseCode();
    }
}