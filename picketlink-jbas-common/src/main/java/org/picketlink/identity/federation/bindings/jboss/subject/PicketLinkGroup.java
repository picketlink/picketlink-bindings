package org.picketlink.identity.federation.bindings.jboss.subject;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * A Principal Group used to register roles in JBoss
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 16, 2009
 */
public class PicketLinkGroup extends PicketLinkPrincipal implements Group {

    private static final long serialVersionUID = 1L;

    private Set<Principal> roles = new HashSet<Principal>();

    public PicketLinkGroup(String name) {
        super(name);
    }

    /**
     * Add a role principal to group
     *
     * @see java.security.acl.Group#addMember(java.security.Principal)
     */
    public boolean addMember(Principal role) {
        return roles.add(role);
    }

    /**
     * Check if the role is a member of the group
     *
     * @see java.security.acl.Group#isMember(java.security.Principal)
     */
    public boolean isMember(Principal role) {
        return roles.contains(role);
    }

    /**
     * Get the group members
     *
     * @see java.security.acl.Group#members()
     */
    public Enumeration<? extends Principal> members() {
        Set<Principal> readOnly = Collections.unmodifiableSet(roles);
        return Collections.enumeration(readOnly);
    }

    /**
     * Remove role from groups
     *
     * @see java.security.acl.Group#removeMember(java.security.Principal)
     */
    public boolean removeMember(Principal user) {
        return roles.remove(user);
    }
}
