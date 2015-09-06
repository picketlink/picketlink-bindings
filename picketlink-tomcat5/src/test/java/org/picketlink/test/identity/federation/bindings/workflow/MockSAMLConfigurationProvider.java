
package org.picketlink.test.identity.federation.bindings.workflow;

import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.config.federation.KeyValueType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.handler.Handler;
import org.picketlink.config.federation.handler.Handlers;
import org.picketlink.identity.federation.web.config.AbstractSAMLConfigurationProvider;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 *
 */
public class MockSAMLConfigurationProvider extends AbstractSAMLConfigurationProvider {
    
    private ProviderType providerType;

    public MockSAMLConfigurationProvider(ProviderType providerType) {
        this.providerType = providerType;
    }

    @Override
    public SPType getSPConfiguration() throws ProcessingException {
        configureDefaultKeyProvider();
        return (SPType) this.providerType;
    }

    private void configureDefaultKeyProvider() {
        this.providerType.setKeyProvider(new KeyProviderType());
        this.providerType.getKeyProvider().setClassName("org.picketlink.identity.federation.core.impl.KeyStoreKeyManager");

        this.providerType.getKeyProvider().add(createAuthProperty("KeyStoreURL", "keystore/jbid_test_keystore.jks"));
        this.providerType.getKeyProvider().add(createAuthProperty("KeyStorePass", "store123"));
        this.providerType.getKeyProvider().add(createAuthProperty("SigningKeyPass", "test123"));
        this.providerType.getKeyProvider().add(createAuthProperty("SigningKeyAlias", "servercert"));

        this.providerType.getKeyProvider().add(createKeyProperty("localhost", "servercert"));
    }

    private KeyValueType createKeyProperty(String key, String value) {
        KeyValueType kv = new KeyValueType();

        kv.setKey(key);
        kv.setValue(value);
        return kv;
    }

    private AuthPropertyType createAuthProperty(String key, String value) {
        AuthPropertyType kv = new AuthPropertyType();

        kv.setKey(key);
        kv.setValue(value);
        return kv;
    }

    private Handler createHandler(String clazz) {
        Handler handler = new Handler();

        handler.setClazz(clazz);

        return handler;
    }

    @Override
    public PicketLinkType getPicketLinkConfiguration() throws ProcessingException {
        PicketLinkType picketLinkType = new PicketLinkType();
        
        picketLinkType.setIdpOrSP(this.providerType);
        
        picketLinkType.setHandlers(new Handlers());

        picketLinkType.getHandlers().add(createHandler("org.picketlink.identity.federation.web.handlers.saml2.SAML2LogOutHandler"));
        picketLinkType.getHandlers().add(createHandler("org.picketlink.identity.federation.web.handlers.saml2.SAML2SignatureValidationHandler"));
        picketLinkType.getHandlers().add(createHandler("org.picketlink.identity.federation.web.handlers.saml2.SAML2AuthenticationHandler"));
        picketLinkType.getHandlers().add(createHandler("org.picketlink.identity.federation.web.handlers.saml2.RolesGenerationHandler"));
        picketLinkType.getHandlers().add(createHandler("org.picketlink.identity.federation.web.handlers.saml2.SAML2SignatureGenerationHandler"));

        return picketLinkType;
    }

    @Override
    public IDPType getIDPConfiguration() throws ProcessingException {
        configureDefaultKeyProvider();
        return (IDPType) this.providerType;
    }
    
}
