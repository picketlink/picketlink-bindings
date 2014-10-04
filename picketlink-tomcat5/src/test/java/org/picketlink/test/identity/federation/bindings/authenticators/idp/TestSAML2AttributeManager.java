/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.test.identity.federation.bindings.authenticators.idp;

import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2AttributeManager;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;

import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Pedro Igor
 */
public class TestSAML2AttributeManager implements SAML2AttributeManager {

    @Override
    public Set<AttributeStatementType> getAttributes(AuthnRequestType authnRequestType, Principal userPrincipal) {
        Set<AttributeStatementType> attributeStatementTypes = new HashSet<AttributeStatementType>();
        AttributeStatementType attrStatement = new AttributeStatementType();
        AttributeType attr = new AttributeType("Attribute1");

        attr.setNameFormat(JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());
        attr.addAttributeValue("AttributeValue1");

        attrStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attr));

        return attributeStatementTypes;
    }

    @Override
    public Map<String, Object> getAttributes(Principal userPrincipal, List<String> attributeKeys) {
        return null;
    }
}
