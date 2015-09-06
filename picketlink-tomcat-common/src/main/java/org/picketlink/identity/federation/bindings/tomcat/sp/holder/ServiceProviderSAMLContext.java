package org.picketlink.identity.federation.bindings.tomcat.sp.holder;

import org.picketlink.identity.federation.core.constants.PicketLinkFederationConstants;

import java.util.List;

/**
 * A context of username/roles to be used by login modules
 *
 * @author Anil.Saldhana@redhat.com
 * @since Feb 13, 2009
 */
public class ServiceProviderSAMLContext {

    public static final String EMPTY_PASSWORD = "EMPTY_STR";

    private static ThreadLocal<String> username = new ThreadLocal<String>();
    private static ThreadLocal<List<String>> userRoles = new ThreadLocal<List<String>>();

    public static void push(String user, List<String> roles) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PicketLinkFederationConstants.RUNTIME_PERMISSION_CORE);
        }
        username.set(user);
        userRoles.set(roles);
    }

    public static void clear() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PicketLinkFederationConstants.RUNTIME_PERMISSION_CORE);
        }
        username.remove();
        userRoles.remove();
    }

    public static String getUserName() {
        return username.get();
    }

    public static List<String> getRoles() {
        return userRoles.get();
    }
}
