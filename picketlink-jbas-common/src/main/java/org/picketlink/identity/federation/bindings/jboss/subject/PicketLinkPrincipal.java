package org.picketlink.identity.federation.bindings.jboss.subject;

import org.jboss.security.SimplePrincipal;

import java.io.Serializable;
import java.security.Principal;

/**
 * Simple Principal
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 16, 2009
 */
public class PicketLinkPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    protected String name;

    private static final String OVERRIDE_EQUALS_BEHAVIOR = "org.picketlink.principal.equals.override";

    public PicketLinkPrincipal(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    @Override
    public int hashCode() {
        return (this.name == null ? 0 : this.name.hashCode());
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Principal)) {
            return false;
        }

        // if the org.picketlink.principal.equals.override system property has been set, narrow the allowed type.
        if ("true".equals(SecurityActions.getSystemProperty(OVERRIDE_EQUALS_BEHAVIOR, "false"))) {
            if (!(obj instanceof SimplePrincipal)) {
                return false;
            }
        }

        // compare the principal names.
        String anotherName = ((Principal) obj).getName();
        boolean equals = false;
        if (this.name == null) {
            equals = anotherName == null;
        } else {
            equals = this.name.equals(anotherName);
        }
        return equals;
    }

    @Override
    public String toString() {
        return this.name;
    }
}
