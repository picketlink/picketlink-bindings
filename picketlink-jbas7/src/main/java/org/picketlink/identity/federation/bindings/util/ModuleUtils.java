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
