
package org.picketlink.test.identity.federation.bindings.authenticators.idp;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 *
 */
public class TestRoleGenerator implements RoleGenerator {

    /* (non-Javadoc)
     * @see org.picketlink.identity.federation.core.interfaces.RoleGenerator#generateRoles(java.security.Principal)
     */
    @Override
    public List<String> generateRoles(Principal principal) {
        ArrayList<String> roles = new ArrayList<String>();
        
        roles.add("test-role1");
        roles.add("test-role2");
        roles.add("test-role3");
        
        return roles;
    }

}
