/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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