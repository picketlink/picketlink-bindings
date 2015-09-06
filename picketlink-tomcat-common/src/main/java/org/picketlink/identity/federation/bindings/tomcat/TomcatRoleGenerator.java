package org.picketlink.identity.federation.bindings.tomcat;

import org.apache.catalina.Role;
import org.apache.catalina.User;
import org.apache.catalina.realm.GenericPrincipal;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Generate roles from Tomcat Principal
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 21, 2009
 */
public class TomcatRoleGenerator implements RoleGenerator {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /**
     * @throws IllegalArgumentException if principal is not of type GenericPrincipal or User
     * @see RoleGenerator#generateRoles(Principal)
     */
    public List<String> generateRoles(Principal principal) {
        String className = principal.getClass().getCanonicalName();

        if (principal instanceof GenericPrincipal == false && principal instanceof User == false) {
            throw logger.wrongTypeError("principal is not tomcat principal:" + className);
        }
        List<String> userRoles = new ArrayList<String>();

        if (principal instanceof GenericPrincipal) {
            GenericPrincipal gp = (GenericPrincipal) principal;
            String[] roles = gp.getRoles();
            if (roles.length > 0) {
                userRoles.addAll(Arrays.asList(roles));
            }
        } else if (principal instanceof User) {
            User tomcatUser = (User) principal;
            Iterator<?> iter = tomcatUser.getRoles();
            while (iter.hasNext()) {
                Role tomcatRole = (Role) iter.next();
                userRoles.add(tomcatRole.getRolename());
            }
        }
        return userRoles;
    }
}
