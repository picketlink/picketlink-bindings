package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.impl.BasicAuthenticationMechanism;

/**
 * PicketLink SP Authentication Mechanism that falls back to BASIC
 * @author Anil Saldhana
 * @since November 04, 2013
 */
public class SPBasicAuthenticationMechanism extends BasicAuthenticationMechanism {
    public SPBasicAuthenticationMechanism(String realmName) {
        super(realmName);
    }

    public SPBasicAuthenticationMechanism(String realmName, String mechanismName) {
        super(realmName, mechanismName);
    }

    public SPBasicAuthenticationMechanism(String realmName, String mechanismName, boolean silent) {
        super(realmName, mechanismName, silent);
    }
}
