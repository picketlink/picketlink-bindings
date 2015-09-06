package org.picketlink.identity.federation.bindings.tomcat;

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Privileged Blocks
 *
 * @author Anil.Saldhana@redhat.com
 * @since Dec 9, 2008
 */
class SecurityActions {

    /**
     * <p> Loads a {@link Class} using the <code>fullQualifiedName</code> supplied. This method tries first to load from the
     * specified {@link Class}, if not found it will try to load from using TCL. </p>
     *
     * @param theClass
     * @param fullQualifiedName
     *
     * @return
     */
    static Class<?> loadClass(final Class<?> theClass, final String fullQualifiedName) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
                public Class<?> run() {
                    ClassLoader classLoader = theClass.getClassLoader();

                    Class<?> clazz = loadClass(classLoader, fullQualifiedName);
                    if (clazz == null) {
                        classLoader = Thread.currentThread().getContextClassLoader();
                        clazz = loadClass(classLoader, fullQualifiedName);
                    }
                    return clazz;
                }
            });
        } else {
            ClassLoader classLoader = theClass.getClassLoader();

            Class<?> clazz = loadClass(classLoader, fullQualifiedName);
            if (clazz == null) {
                classLoader = Thread.currentThread().getContextClassLoader();
                clazz = loadClass(classLoader, fullQualifiedName);
            }
            return clazz;
        }
    }

    /**
     * <p> Loads a class from the specified {@link ClassLoader} using the <code>fullQualifiedName</code> supplied. </p>
     *
     * @param classLoader
     * @param fullQualifiedName
     *
     * @return
     */
    static Class<?> loadClass(final ClassLoader classLoader, final String fullQualifiedName) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
                public Class<?> run() {
                    try {
                        return classLoader.loadClass(fullQualifiedName);
                    } catch (ClassNotFoundException e) {
                    }
                    return null;
                }
            });
        } else {
            try {
                return classLoader.loadClass(fullQualifiedName);
            } catch (ClassNotFoundException e) {
            }
            return null;
        }
    }

    /**
     * Get a system property
     *
     * @param key the key for the property
     * @param defaultValue A default value to return if the property is not set (Can be null)
     *
     * @return
     */
    static String getProperty(final String key, final String defaultValue) {
        if (System.getSecurityManager() != null) {
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
