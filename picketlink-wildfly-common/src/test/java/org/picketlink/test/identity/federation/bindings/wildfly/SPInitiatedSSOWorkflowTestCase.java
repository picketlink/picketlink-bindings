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
package org.picketlink.test.identity.federation.bindings.wildfly;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.SubmitButton;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceChangeListener;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.server.handlers.resource.URLResource;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.FilterInfo;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.ServletContainer;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.junit.Before;
import org.junit.Test;
import org.picketlink.identity.federation.bindings.wildfly.sp.SPServletExtension;
import org.picketlink.identity.federation.web.filters.IDPFilter;

import javax.servlet.DispatcherType;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.net.URL;
import java.security.Principal;

import static junit.framework.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Simple Workflow for SAML SSO using Undertow
 * @author Anil Saldhana
 * @since November 14, 2013
 */
public class SPInitiatedSSOWorkflowTestCase extends UndertowTestCase {

    protected final PathHandler path = new PathHandler();
    private WebConversation webConversation = null;
    private WebResponse webResponse = null;
    private int responseCode = 0;

    @Override
    protected HttpHandler getHandler() {
        System.out.println("Inside SPInitiatedSSOWorkflowTestCase -> getHandler");
        return path;
    }

    @Before
    public void setup() throws Exception{
        super.setup();
        assertNotNull(server);
        deployIDP();
        deploySP();
    }

    protected String getContextPathShortForm(){
        return "sp";
    }

    public void deployIDP() throws Exception{
        final ServletContainer container = ServletContainer.Factory.newInstance();
        FilterInfo idpFilterInfo = new FilterInfo("IDPFilter", IDPFilter.class);

        ServletInfo regularServletInfo = new ServletInfo("servlet", SendUsernameServlet.class)
                .setServletSecurityInfo(new ServletSecurityInfo()
                        .addRoleAllowed("role1"))
                .addMapping("/*")
                ;

        ServletInfo formServletInfo = new ServletInfo("loginPage", FormLoginServlet.class)
                .setServletSecurityInfo(new ServletSecurityInfo()
                        .addRoleAllowed("group1"))
                .addMapping("/FormLoginServlet");

        TestIdentityManager identityManager = new TestIdentityManager();
        identityManager.addUser("user1", "password1", "role1");

        LoginConfig loginConfig = new LoginConfig("FORM", "Test Realm", "/FormLoginServlet","/error.html");

        DeploymentInfo deploymentInfo = new DeploymentInfo()
                .setClassLoader(SPInitiatedSSOWorkflowTestCase.class.getClassLoader())
                .setContextPath("/idp")
                .setDeploymentName("idp.war")
                .setClassIntrospecter(TestClassIntrospector.INSTANCE)
                .setIdentityManager(identityManager)
                .setLoginConfig(loginConfig)
                .setResourceManager(new TestResourceManager("idp"))
                .addServlets(regularServletInfo, formServletInfo)
                .addFilter(idpFilterInfo)
                .addFilterUrlMapping(idpFilterInfo.getName(), "/*", DispatcherType.REQUEST);

        DeploymentManager manager = container.addDeployment(deploymentInfo);
        manager.deploy();

        try{
            path.addPath(deploymentInfo.getContextPath(), manager.start());
        }catch(ServletException se){
            throw new RuntimeException(se);
        }
        System.out.println("Deployment success:" + deploymentInfo.getContextPath());
    }

    public void deploySP() throws Exception{
        final ServletContainer container = ServletContainer.Factory.newInstance();

        ServletInfo welcomeServlet = new ServletInfo("/", WelcomeServlet.class)
                .addMapping("/WelcomeServlet");

        ServletInfo regularServletInfo = new ServletInfo("servlet", SendUsernameServlet.class)
                .setServletSecurityInfo(new ServletSecurityInfo()
                        .addRoleAllowed("role1"))
                .addMapping("/secured/*");

        ServletInfo formServletInfo = new ServletInfo("loginPage", FormLoginServlet.class)
                .setServletSecurityInfo(new ServletSecurityInfo()
                        .addRoleAllowed("group1"))
                .addMapping("/FormLoginServlet");

        TestIdentityManager identityManager = new TestIdentityManager();
        identityManager.addUser("user1", "password1", "role1");

        LoginConfig loginConfig = new LoginConfig("FORM", "Test Realm", "/FormLoginServlet","/error.html");

        ResourceManager resourceManager = new TestResourceManager(getContextPathShortForm());

        DeploymentInfo deploymentInfo = new DeploymentInfo()
                .setClassLoader(SPInitiatedSSOWorkflowTestCase.class.getClassLoader())
                .setContextPath("/"+getContextPathShortForm())
                .setDeploymentName(getContextPathShortForm() + ".war")
                .setClassIntrospecter(TestClassIntrospector.INSTANCE)
                .setIdentityManager(identityManager)
                .setLoginConfig(loginConfig)
                .setResourceManager(resourceManager)
                .addServlets(regularServletInfo, formServletInfo)
                .addServletExtension(new SPServletExtension());

        DeploymentManager manager = container.addDeployment(deploymentInfo);
        manager.deploy();

        try{
            path.addPath(deploymentInfo.getContextPath(), manager.start());
        }catch(ServletException se){
            throw new RuntimeException(se);
        }
        System.out.println("Deployment success:" + deploymentInfo.getContextPath());
    }

    public static class WelcomeServlet extends HttpServlet {
        @Override
        protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
            OutputStream stream = resp.getOutputStream();
            stream.write("Welcome".getBytes());
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
        protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
            OutputStream stream = resp.getOutputStream();
            Principal principal = req.getUserPrincipal();
            String name = principal.getName();
            stream.write(name.getBytes());
        }
    }
    /*
     * @author Stuart Douglas
     */
    public static class FormLoginServlet extends HttpServlet {

        @Override
        protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
            Writer writer = resp.getWriter();
            writer.write("Login Page");
            writer.write("<form id=\"login_form\" name=\"login_form\" method=\"post\"\n" +
                    "                        action=\"j_security_check\" enctype=\"application/x-www-form-urlencoded\">\n" +
                    "                        <div style=\"margin-left: 15px;\">\n" +
                    "                                <p>\n" +
                    "                                        <label for=\"username\"> Username</label><br /> <input id=\"username\"\n" +
                    "                                                type=\"text\" name=\"j_username\" size=\"20\" />\n" +
                    "                                </p>\n" +
                    "                                <p>\n" +
                    "                                        <label for=\"password\"> Password</label><br /> <input id=\"password\"\n" +
                    "                                                type=\"password\" name=\"j_password\" value=\"\" size=\"20\" />\n" +
                    "                                </p>\n" +
                    "                                <center>\n" +
                    "                                        <input id=\"submit\" type=\"submit\" name=\"submit\" value=\"Login\"\n" +
                    "                                                class=\"buttonmed\" />\n" +
                    "                                </center>\n" +
                    "                        </div>\n" +
                    "                </form>");

        }
    }


    @Test
    public void testServerUp() throws Exception{
    }

    public class TestResourceManager implements ResourceManager{

        private final String basePath;

        public TestResourceManager(String basePath){
            this.basePath = basePath;
        }

        @Override
        public Resource getResource(String path) throws IOException {
            String temp = path;
            //Remove WEB-INF
            temp = temp.replace("/WEB-INF","");

            URL url = getClass().getClassLoader().getResource(basePath+temp);
            return new URLResource(url, url.openConnection(), path);
        }

        @Override
        public boolean isResourceChangeListenerSupported() {
            throw new RuntimeException();
        }

        @Override
        public void registerResourceChangeListener(ResourceChangeListener listener) {
            throw new RuntimeException();
        }

        @Override
        public void removeResourceChangeListener(ResourceChangeListener listener) {
            throw new RuntimeException();
        }

        @Override
        public void close() throws IOException {
            throw new RuntimeException();
        }
    }

    @Test
    public void testSSO() throws Exception{
        String spURI = "http://localhost:8080/"+ getContextPathShortForm() + "/secured/test";
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

    private String readResponse(final HttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        if(entity == null) {
            return "";
        }
        return readResponse(entity.getContent());
    }
    private String readResponse(InputStream stream) throws IOException {
        final StringBuilder builder = new StringBuilder();
        byte[] data = new byte[100];
        int read;
        while ((read = stream.read(data)) != -1) {
            builder.append(new String(data,0,read,"UTF-8"));
        }
        return builder.toString();
    }
    private void handle303() throws Exception {
        String otherLocation = webResponse.getHeaderField("LOCATION");
        webResponse = webConversation.getResponse(otherLocation);
        responseCode = webResponse.getResponseCode();
    }
}