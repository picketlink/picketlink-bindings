
package org.picketlink.identity.federation.bindings.jboss.auth;

import org.jboss.security.JBossJSSESecurityDomain;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.security.KeyStore;

/**
 * This LoginModule authenticates clients by validating their SAML assertions locally. If the supplied assertion contains roles,
 * these roles are extracted and included in the Group returned by the getRoleSets method. The LoginModule is designed to validate
 * SAML token using X509 certificate stored in XML signature within SAML assertion token.
 *
 * It validates: <ol> <li>CertPath against specified truststore. It has to have common valid public certificate in the trusted
 * entries.</li> <li>X509 certificate stored in SAML token didn't expire</li> <li>if signature itself is valid</li> <li>SAML token
 * expiration</li> </ol>
 *
 * This module defines the following module options:
 *
 * roleKey: key of the attribute name that we need to use for Roles from the SAML assertion. This can be a comma-separated string
 * values such as (Role,Membership) localValidationSecurityDomain: the security domain for the trust store information (via the
 * JaasSecurityDomain) cache.invalidation - set it to true if you require invalidation of JBoss Auth Cache at SAML Principal
 * expiration. jboss.security.security_domain -security domain at which Principal will expire if cache.invalidation is used.
 * tokenEncodingType: encoding type of SAML token delivered via http request's header. Possible values are: base64 - content encoded
 * as base64. In case of encoding will vary between base64 and gzip use base64 and LoginModule will detect gzipped data. gzip -
 * gzipped content encoded as base64 none - content not encoded in any way samlTokenHttpHeader - name of http request header to
 * fetch SAML token from. For example: "Authorize" samlTokenHttpHeaderRegEx - Java regular expression to be used to get SAML token
 * from "samlTokenHttpHeader". Example: use: ."(.)".* to parse SAML token from header content like this: SAML_assertion="HHDHS=", at
 * the same time set samlTokenHttpHeaderRegExGroup to 1. samlTokenHttpHeaderRegExGroup - Group value to be used when parsing out
 * value of http request header specified by "samlTokenHttpHeader" using "samlTokenHttpHeaderRegEx".
 *
 * @author Peter Skopek: pskopek at redhat dot com
 */
public class SAMLTokenCertValidatingLoginModule extends
    SAMLTokenCertValidatingCommonLoginModule {

    /**
     * AS7/EAP6 way of getting configured keyStore. uses module-option: localValidationSecurityDomain.
     *
     * @return
     *
     * @throws Exception
     */
    protected KeyStore getKeyStore() throws Exception {

        // get keystore
        Context ctx = new InitialContext();
        String jsseLookupString = localValidationSecurityDomain + "/jsse";

        JBossJSSESecurityDomain sd = (JBossJSSESecurityDomain) ctx.lookup(jsseLookupString);
        String securityDomain = sd.getSecurityDomain();

        KeyStore ts = sd.getTrustStore();
        if (ts == null) {
            throw logger.authNullKeyStoreFromSecurityDomainError(securityDomain);
        }

        return ts;
    }
}
