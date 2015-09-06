package org.picketlink.identity.federation.bindings.servlets;

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Privileged Blocks
 *
 * @author Anil.Saldhana@redhat.com
 * @since Mar 17, 2009
 */
class SecurityActions {

    static void setSystemProperty(final String key, final String value) {
        if (System.getSecurityManager() != null) {
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                public Object run() {
                    System.setProperty(key, value);
                    return null;
                }
            });
        } else {
            System.setProperty(key, value);
        }
    }
}
