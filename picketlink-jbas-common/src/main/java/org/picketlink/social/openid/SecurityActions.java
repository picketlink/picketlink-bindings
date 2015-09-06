package org.picketlink.social.openid;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Privileged Blocks
 *
 * @author Anil Saldhana
 * @since May 19, 2011
 */
class SecurityActions {

    static SecurityContext createSecurityContext(final String name) {
        return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>() {
            public SecurityContext run() {
                try {
                    return SecurityContextFactory.createSecurityContext(name);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    static void setSecurityContext(final SecurityContext sc) {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {

            public Void run() {
                SecurityContextAssociation.setSecurityContext(sc);
                return null;
            }
        });
    }

    static SecurityContext getSecurityContext() {
        return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>() {

            public SecurityContext run() {
                return SecurityContextAssociation.getSecurityContext();
            }
        });
    }

    static ClassLoader getContextClassLoader() {
        return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {

            public ClassLoader run() {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }

    /**
     * Use reflection to get the {@link java.lang.reflect.Method} on a {@link Class} with the given parameter types
     *
     * @param clazz
     * @param methodName
     * @param parameterTypes
     *
     * @return
     */
    static Method getMethod(final Class<?> clazz, final String methodName, final Class<?>[] parameterTypes) {
        return AccessController.doPrivileged(new PrivilegedAction<Method>() {
            public Method run() {
                try {
                    return clazz.getDeclaredMethod(methodName, parameterTypes);
                } catch (Exception e) {
                    return null;
                }
            }
        });
    }

    /**
     * Using the caller class, try to load a class using its classloader. If unsuccessful, use the TCCL
     *
     * @param theAskingClass
     * @param fqn
     *
     * @return
     */
    static Class<?> loadClass(final Class<?> theAskingClass, final String fqn) {
        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
            public Class<?> run() {
                try {
                    ClassLoader tcl = theAskingClass.getClassLoader();
                    return tcl.loadClass(fqn);
                } catch (Exception e) {
                    try {
                        return Thread.currentThread().getContextClassLoader().loadClass(fqn);
                    } catch (ClassNotFoundException e1) {
                        return null;
                    }
                }
            }
        });
    }
}
