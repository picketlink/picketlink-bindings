package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.api.NonceManager;
import io.undertow.security.idm.DigestAlgorithm;
import io.undertow.security.impl.DigestAuthenticationMechanism;
import io.undertow.security.impl.DigestQop;

import java.util.List;

/**
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
