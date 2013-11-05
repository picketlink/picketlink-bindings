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
package org.picketlink.identity.federation.bindings.wildfly.idp;

import static io.undertow.security.api.SecurityNotification.EventType;
import io.undertow.security.api.NotificationReceiver;
import io.undertow.security.api.SecurityNotification;
import io.undertow.security.idm.Account;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HeaderMap;
import org.jboss.security.audit.AuditEvent;
import org.jboss.security.audit.AuditLevel;
import org.jboss.security.audit.AuditManager;
import org.picketlink.identity.federation.bindings.wildfly.events.PicketLinkEventNotification;
import org.picketlink.identity.federation.bindings.wildfly.events.PicketLinkEventNotificationHandler;
import org.picketlink.identity.federation.bindings.wildfly.events.RestartNotification;
import org.picketlink.identity.federation.bindings.wildfly.events.UpdateConfigurationNotification;

import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class for the PicketLink Identity Provider
 * @author Anil Saldhana
 * @since November 04, 2013
 */
public abstract class AbstractIDPHandler implements HttpHandler, NotificationReceiver,PicketLinkEventNotificationHandler {
    //Audit Manager
    private final AuditManager auditManager = null;

    protected volatile HttpHandler nextHandler;

    public AbstractIDPHandler(HttpHandler nextHandler){
        this.nextHandler = nextHandler;
    }

    public HttpHandler getNext(){
        return this.nextHandler;
    }

    public AbstractIDPHandler setNext(HttpHandler next){
        this.nextHandler = next;
        return this;
    }

    @Override
    public void handleNotification(SecurityNotification securityNotification) {
        //TODO: audit manager injection
        if(auditManager == null){
            throw new IllegalStateException();
        }
        //Audit the security events
        SecurityNotification.EventType event = securityNotification.getEventType();
        if (event == EventType.AUTHENTICATED || event == EventType.FAILED_AUTHENTICATION) {
            String auditLevel = AuditLevel.SUCCESS;
            if(event != EventType.AUTHENTICATED){
                auditLevel = AuditLevel.FAILURE;
            }
            AuditEvent auditEvent = new AuditEvent(auditLevel);
            Map<String, Object> ctxMap = new HashMap<String, Object>();
            Account account = securityNotification.getAccount();
            if (account != null) {
                ctxMap.put("principal", account.getPrincipal().getName());
            }
            ctxMap.put("message", securityNotification.getMessage());
            ctxMap.put("Source", getClass().getCanonicalName());
            auditEvent.setContextMap(ctxMap);
            auditManager.audit(auditEvent);
        }
    }



    @Override
    public void handle(PicketLinkEventNotification event) {
        if(event instanceof UpdateConfigurationNotification){
            //Reload config
            loadConfiguration();
        }else if(event instanceof RestartNotification){
            //We need to restart this handler's state
        }
    }

    @Override
    public void handleRequest(HttpServerExchange httpServerExchange) throws Exception {
       HeaderMap headerMap = httpServerExchange.getRequestHeaders();
       //TODO: get session

        nextHandler.handleRequest(httpServerExchange);
    }

    /**
     * Load the configuration
     */
    protected abstract void loadConfiguration();
}