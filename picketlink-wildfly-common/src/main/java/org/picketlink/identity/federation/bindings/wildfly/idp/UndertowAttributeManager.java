package org.picketlink.identity.federation.bindings.wildfly.idp;

import org.picketlink.identity.federation.core.interfaces.AttributeManager;

import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * Instance of {@link org.picketlink.identity.federation.core.interfaces.AttributeManager} for Undertow
 * @author Anil Saldhana
 * @since December 06, 2013
 */
public class UndertowAttributeManager implements AttributeManager {
    @Override
    public Map<String, Object> getAttributes(Principal userPrincipal, List<String> attributeKeys) {
        return null;
    }
}
