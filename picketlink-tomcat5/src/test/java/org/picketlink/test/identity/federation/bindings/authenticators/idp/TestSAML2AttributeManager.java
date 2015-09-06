package org.picketlink.test.identity.federation.bindings.authenticators.idp;

import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2AttributeManager;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;

import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.picketlink.identity.federation.core.saml.v2.util.StatementUtil.createAttributeStatement;

/**
 * @author Pedro Igor
 */
public class TestSAML2AttributeManager implements SAML2AttributeManager {

    @Override
    public Set<AttributeStatementType> getAttributes(AuthnRequestType authnRequestType, Principal userPrincipal) {
        Set<AttributeStatementType> attributeStatementTypes = new HashSet<AttributeStatementType>();

        attributeStatementTypes.add(createAttributeStatement("attribute1", "attributeValue1"));
        attributeStatementTypes.add(createAttributeStatement("attribute2", "attributeValue2"));
        attributeStatementTypes.add(createAttributeStatement("attribute3", "attributeValue3"));

        return attributeStatementTypes;
    }

    @Override
    public Map<String, Object> getAttributes(Principal userPrincipal, List<String> attributeKeys) {
        return null;
    }
}
