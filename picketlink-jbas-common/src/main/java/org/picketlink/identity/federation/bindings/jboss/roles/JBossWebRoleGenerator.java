package org.picketlink.identity.federation.bindings.jboss.roles;

import org.apache.catalina.connector.Request;
import org.jboss.security.SimplePrincipal;
import org.picketlink.identity.federation.bindings.tomcat.TomcatRoleGenerator;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.List;

/**
 * {@link org.picketlink.identity.federation.core.interfaces.RoleGenerator} for JBossWeb
 *
 * @author Anil Saldhana
 * @since February 21, 2014
 */
public class JBossWebRoleGenerator extends TomcatRoleGenerator {

    @Override
    public List<String> generateRoles(Principal principal) {
        if (principal instanceof SimplePrincipal) {
            //Use JACC to get the request
            try {
                HttpServletRequest request =
                    (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
                if (request instanceof Request) {
                    Request catalinaRequest = (Request) request;
                    return super.generateRoles(catalinaRequest.getPrincipal());
                }
            } catch (PolicyContextException e) {
                throw new RuntimeException(e);
            }
        } else {
            return super.generateRoles(principal);
        }
        return null;
    }
}
