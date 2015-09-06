package org.picketlink.identity.federation.bindings.jboss.subject;

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * <p> This class contains operations that need privileged blocks to run. </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
class SecurityActions {

    /**
     * <p>Returns a system property value using the specified <code>key</code>. If not found the <code>defaultValue</code> will be
     * returned.</p>
     *
     * @param key
     * @param defaultValue
     *
     * @return
     */
    static String getSystemProperty(final String key, final String defaultValue) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty(key, defaultValue);
                }
            });
        } else {
            return System.getProperty(key, defaultValue);
        }
    }
}
