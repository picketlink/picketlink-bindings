package org.picketlink.identity.federation.bindings.tomcat;

import org.picketlink.identity.federation.core.interfaces.AttributeManager;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An implementation of attribute manager to get attributes of an identity
 *
 * @author Anil.Saldhana@redhat.com
 * @since Aug 31, 2009
 */
public class TomcatAttributeManager implements AttributeManager {

    /**
     * @see AttributeManager#getAttributes(Principal, List)
     */
    public Map<String, Object> getAttributes(Principal userPrincipal, List<String> attributeKeys) {
        return new HashMap<String, Object>();
    }
}
