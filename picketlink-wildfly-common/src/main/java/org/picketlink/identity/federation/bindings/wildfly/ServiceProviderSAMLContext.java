package org.picketlink.identity.federation.bindings.wildfly;

import java.util.List;

public class ServiceProviderSAMLContext {
    public static final String EMPTY_PASSWORD = "EMPTY_STR";

    private static ThreadLocal<String> username = new ThreadLocal<String>();
    private static ThreadLocal<List<String>> userRoles = new ThreadLocal<List<String>>();

    public static void push(String user, List<String> roles) {
        username.set(user);
        userRoles.set(roles);
    }

    public static void clear() {
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
