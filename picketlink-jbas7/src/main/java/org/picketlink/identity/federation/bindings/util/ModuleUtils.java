
package org.picketlink.identity.federation.bindings.util;

import java.security.AccessController;
import java.security.PrivilegedAction;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleClassLoader;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig;

/**
 * Utility class to work with modules.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class ModuleUtils {

    public static String getCurrentModuleId() {

        ClassLoader tccl;

        if (System.getSecurityManager() != null) {
            tccl =  AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            });
        } else {
            tccl = Thread.currentThread().getContextClassLoader();
        }

        if (tccl != null && tccl instanceof ModuleClassLoader) {
            Module m = ((ModuleClassLoader) tccl).getModule();
            if (m != null) {
                return m.getIdentifier().getName();
            }
            return STSClientConfig.NO_MODULE;
        }
        else {
            return STSClientConfig.NO_MODULE;
        }
    }

}
