package org.picketlink.identity.federation.bindings.wildfly.rest;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.web.util.PostBindingUtil;

/**
 * Generates a SAML Assertion for an User
 *
 * @author Anil Saldhana
 * @since June 05, 2014
 */
@Path("/saml")
public class SAMLEndpoint extends STSEndpoint {

    @POST
    public Response generateAssertion(@Context HttpServletRequest httpServletRequest,
            @Context HttpServletResponse httpServletResponse) throws Exception {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal == null) {
            // Send Error Response
            return Response.status(403).build();
        }
        SAMLProtocolContext samlProtocolContext = getSAMLProtocolContext(principal.getName());
        AssertionType assertionType = issueSAMLAssertion(samlProtocolContext);
        // TODO: sign/encrypt
        String base64EncodedAssertion = PostBindingUtil.base64Encode(AssertionUtil.asString(assertionType));

        return Response.status(200).entity(base64EncodedAssertion).build();
    }
}
