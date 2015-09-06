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
