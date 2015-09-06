package org.picketlink.social.openid.providers;

import javax.xml.namespace.QName;

/**
 * A {@code SecurityTokenProvider} implementation for Open ID v2
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 20, 2011
 */
public class OpenIDVersion2TokenProvider extends OpenIDTokenProvider {

    @Override
    public boolean supports(String namespace) {
        return OPENID_2_0_NS.equals(namespace);
    }

    @Override
    public String tokenType() {
        return OPENID_2_0_NS;
    }

    @Override
    public QName getSupportedQName() {
        return new QName(OPENID_2_0_NS);
    }
}
