package org.picketlink.identity.federation.bindings.jetty.idp;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;

import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

/**
 * An implementation of {@link org.picketlink.identity.federation.core.interfaces.RoleGenerator}
 * for Jetty that peeks into the {@link javax.security.auth.Subject} available in the Jetty
 * identity
 * @author Anil Saldhana
 * @since December 09, 2013
 */
public class JettyRoleGenerator implements RoleGenerator{
    @Override
    public List<String> generateRoles(Principal principal) {
        List<String> roles = new ArrayList<String>();

        Request request = HttpChannel.getCurrentHttpChannel().getRequest();
        if(request != null){
            UserIdentity theIdentity = request.getResolvedUserIdentity();
            Subject theSubject = theIdentity.getSubject();

            //We assume that the principals other than the user principal represent roles
            Set<Principal> principalSet = theSubject.getPrincipals();
            if(!principalSet.isEmpty()){
                for(Principal aPrincipal: principalSet){
                    if(principal != aPrincipal){
                        roles.add(aPrincipal.getName());
                    }
                }
            }
        }
        return roles;
    }
}
