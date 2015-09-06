package org.picketlink.identity.federation.bindings.tomcat.sp;

import java.lang.reflect.Method;
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

    /**
     * Use reflection to get the {@link Method} on a {@link Class} with the given parameter types
     *
     * @param clazz
     * @param methodName
     * @param parameterTypes
     *
     * @return
     */
    static Method getMethod(final Class<?> clazz, final String methodName, final Class<?>[] parameterTypes) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Method>() {
                public Method run() {
                    try {
                        return clazz.getDeclaredMethod(methodName, parameterTypes);
                    } catch (Exception e) {
                        return null;
                    }
                }
            });
        } else {
            try {
                return clazz.getDeclaredMethod(methodName, parameterTypes);
            } catch (Exception e) {
                return null;
            }
        }
    }
}
