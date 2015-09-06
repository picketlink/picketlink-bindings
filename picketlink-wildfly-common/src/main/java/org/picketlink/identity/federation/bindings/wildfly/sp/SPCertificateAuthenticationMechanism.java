package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.impl.ClientCertAuthenticationMechanism;

/**
 * PicketLink SP Authentication Mechanism that falls back to CLIENT-CERT
 * @author Anil Saldhana
 * @since November 04, 2013
 */
public class SPCertificateAuthenticationMechanism extends ClientCertAuthenticationMechanism {
}
