package org.picketlink.identity.federation.bindings.jboss.attribute;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.identity.Attribute;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingType;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.interfaces.AttributeManager;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An attribute manager implementation for JBAS
 *
 * @author Anil.Saldhana@redhat.com
 * @since Sep 8, 2009
 */
public class JBossAppServerAttributeManager implements AttributeManager {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /**
     * @see AttributeManager#getAttributes(Principal, List)
     */
    public Map<String, Object> getAttributes(Principal userPrincipal, List<String> attributeKeys) {
        Map<String, Object> attributeMap = new HashMap<String, Object>();

        SecurityContext sc = SecurityActions.getSecurityContext();
        if (sc != null) {
            String mappingType = MappingType.ATTRIBUTE.name();
            MappingManager mm = sc.getMappingManager();
            MappingContext<List<Attribute<Object>>> mc = mm.getMappingContext(mappingType);

            if (mc == null) {
                logger.mappingContextNull();
                return attributeMap;
            }

            Map<String, Object> contextMap = new HashMap<String, Object>();
            contextMap.put(SecurityConstants.PRINCIPAL_IDENTIFIER, userPrincipal);

            List<Attribute<Object>> attList = new ArrayList<Attribute<Object>>();

            try {
                mc.performMapping(contextMap, attList);
            } catch (Exception e) {
                logger.attributeManagerError(e);
            }
            attList = (List<Attribute<Object>>) mc.getMappingResult().getMappedObject();

            if (attList != null) {
                for (Attribute<Object> attribute : attList) {
                    attributeMap.put(attribute.getName(), attribute.getValue());
                }
            }
        } else {
            logger.couldNotObtainSecurityContext();
        }

        if (attributeMap != null) {
            logger.trace("Final attribute map size: " + attributeMap.size());
        }

        return attributeMap;
    }
}
