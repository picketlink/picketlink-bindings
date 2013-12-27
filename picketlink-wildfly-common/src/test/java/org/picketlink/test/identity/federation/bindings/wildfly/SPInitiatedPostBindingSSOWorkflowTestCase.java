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

import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.InstanceFactory;
import io.undertow.servlet.api.InstanceHandle;
import io.undertow.servlet.api.ListenerInfo;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.ServletContainer;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import org.junit.Before;
import org.junit.Test;
import org.picketlink.identity.federation.bindings.wildfly.sp.SPFormAuthenticationMechanism;

import javax.servlet.ServletException;
import java.util.EventListener;

import static junit.framework.Assert.assertNotNull;

/**
 * Unit test the SP Initiated Workflow with HTTP/POST Binding
 * @author Anil Saldhana
 * @since December 27, 2013
 */
public class SPInitiatedPostBindingSSOWorkflowTestCase extends SPInitiatedSSOWorkflowTestCase{
    @Override
    protected String getContextPathShortForm() {
        return "sp_post";
    }
    @Test
    public void testServerUp() throws Exception{
    }
}