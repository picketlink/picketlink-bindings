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
package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.saml.workflow.ServiceProviderSAMLWorkflow;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

import static org.picketlink.common.util.StringUtil.isNotNull;

/**
 * Implementation of {@link org.picketlink.identity.federation.core.saml.workflow.ServiceProviderSAMLWorkflow.RedirectionHandler}
 * for Undertow
 *
 * @author Anil Saldhana
 * @since December 27, 2013
 */
public class UndertowRedirectionHandler extends ServiceProviderSAMLWorkflow.RedirectionHandler {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    private HttpServerExchange httpServerExchange = null;

    public UndertowRedirectionHandler(HttpServerExchange httpServerExchange){
        this.httpServerExchange = httpServerExchange;
    }

    @Override
    public void sendPost(DestinationInfoHolder holder, HttpServletResponse response, boolean willSendRequest) throws IOException {
        String key = willSendRequest ? GeneralConstants.SAML_REQUEST_KEY : GeneralConstants.SAML_RESPONSE_KEY;

        String relayState = holder.getRelayState();
        String destination = holder.getDestination();
        String samlMessage = holder.getSamlMessage();

        if (destination == null) {
            throw logger.nullValueError("Destination is null");
        }

        response.setContentType("text/html");
        commonForPost();
        StringBuilder builder = new StringBuilder();

        builder.append("<HTML>");
        builder.append("<HEAD>");

        if (willSendRequest)
            builder.append("<TITLE>HTTP Post Binding (Request)</TITLE>");
        else
            builder.append("<TITLE>HTTP Post Binding Response (Response)</TITLE>");

        builder.append("</HEAD>");
        builder.append("<BODY Onload=\"document.forms[0].submit()\">");

        builder.append("<FORM METHOD=\"POST\" ACTION=\"" + destination + "\">");
        builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"" + key + "\"" + " VALUE=\"" + samlMessage + "\"/>");

        if (isNotNull(relayState)) {
            builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"RelayState\" " + "VALUE=\"" + relayState + "\"/>");
        }

        builder.append("<NOSCRIPT>");
        builder.append("<P>JavaScript is disabled. We strongly recommend to enable it. Click the button below to continue.</P>");
        builder.append("<INPUT TYPE=\"SUBMIT\" VALUE=\"CONTINUE\" />");
        builder.append("</NOSCRIPT>");

        builder.append("</FORM></BODY></HTML>");

        String str = builder.toString();

        logger.trace(str);

        OutputStream outputStream = httpServerExchange.getOutputStream();

        outputStream.write(str.getBytes("UTF-8"));
        outputStream.close();
    }

    @Override
    public void sendRedirectForRequestor(String destination, HttpServletResponse response) throws IOException {
        commonForRedirect(destination);
        httpServerExchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-cache, no-store");
    }

    @Override
    public void sendRedirectForResponder(String destination, HttpServletResponse response) throws IOException {
        commonForRedirect(destination);
        httpServerExchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-cache, no-store, must-revalidate,private");
    }

    private void commonForRedirect(String destination) throws IOException{
        httpServerExchange.getResponseHeaders().put(Headers.CONTENT_ENCODING, "UTF-8");
        httpServerExchange.getResponseHeaders().put(Headers.PRAGMA, "no-cache");
        httpServerExchange.getResponseHeaders().put(Headers.LOCATION, destination);
    }

    private void commonForPost(){
        httpServerExchange.getResponseHeaders().put(Headers.CONTENT_ENCODING, "UTF-8");
        httpServerExchange.getResponseHeaders().put(Headers.PRAGMA, "no-cache");
        httpServerExchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-cache, no-store");
    }
}
