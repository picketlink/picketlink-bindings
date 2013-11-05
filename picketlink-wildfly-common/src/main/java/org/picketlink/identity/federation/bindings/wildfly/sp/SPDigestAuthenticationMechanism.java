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
package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.api.NonceManager;
import io.undertow.security.idm.DigestAlgorithm;
import io.undertow.security.impl.DigestAuthenticationMechanism;
import io.undertow.security.impl.DigestQop;

import java.util.List;

/**
 *
 * PicketLink SP Authentication Mechanism that falls back to DIGEST
 * @author Anil Saldhana
 * @since November 04, 2013
 */
public class SPDigestAuthenticationMechanism extends DigestAuthenticationMechanism {
    public SPDigestAuthenticationMechanism(List<DigestAlgorithm> supportedAlgorithms,
                                           List<DigestQop> supportedQops, String realmName, String domain,
                                           NonceManager nonceManager) {
        super(supportedAlgorithms, supportedQops, realmName, domain, nonceManager);
    }

    public SPDigestAuthenticationMechanism(List<DigestAlgorithm> supportedAlgorithms,
                                           List<DigestQop> supportedQops, String realmName, String domain,
                                           NonceManager nonceManager, String mechanismName) {
        super(supportedAlgorithms, supportedQops, realmName, domain, nonceManager, mechanismName);
    }

    public SPDigestAuthenticationMechanism(String realmName, String domain, String mechanismName) {
        super(realmName, domain, mechanismName);
    }
}