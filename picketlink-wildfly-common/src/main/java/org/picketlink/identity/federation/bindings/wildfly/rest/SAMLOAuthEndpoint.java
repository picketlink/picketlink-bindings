package org.picketlink.identity.federation.bindings.wildfly.rest;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;

/**
 * JAX-RS Endpoint for exchanging SAML Assertions with OAuth tokens
 *
 * @author Anil Saldhana
 * @since April 30, 2014
 */
@Path("/samloauth")
public class SAMLOAuthEndpoint extends STSEndpoint {
    private static final long serialVersionUID = 1L;
    private static Logger log = Logger.getLogger(SAMLOAuthEndpoint.class.getName());

    private boolean debugEnabled = log.isDebugEnabled();

    @POST
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response exchange(@Context HttpServletRequest request) throws Exception {
        Principal principal = request.getUserPrincipal();
        if (principal == null) {
            // We are not authenticated
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        String grantType = request.getParameter(GRANT_TYPE_PARAMETER);
        if (grantType == null) {
            if(debugEnabled){
                log.debug("Grant Type parameter missing");
            }
            return Response.status(Response.Status.NOT_FOUND).build();// no grant type
        }
        if (grantType.equals(GRANT_TYPE) == false) {
            if(debugEnabled){
                log.debug("Wrong Grant Type:" + grantType);
            }
            return Response.status(Response.Status.NOT_FOUND).build();// Wrong Grant Type
        }
        String samlToken = request.getParameter(ASSERTION_PARAMETER);
        if (samlToken == null) {
            if(debugEnabled){
                log.debug("No SAML Assertion Found");
            }
            return Response.status(Response.Status.NOT_FOUND).build();// no token
        }

        AssertionType assertionType = parseAssertion(samlToken);

        if (AssertionUtil.hasExpired(assertionType)) {
            log.error("Expired Assertion with ID = " + assertionType.getID());
            return Response.status(Response.Status.NOT_ACCEPTABLE).build();// expired assertion
        }

        String assertionID = assertionType.getID();

        String oauthToken = issueOAuthToken(assertionID);
        if (oauthToken == null) {
            Response.serverError().build();
        }
        SAMLOauthInfo samlOauthInfo = new SAMLOauthInfo(assertionID, oauthToken);
        return Response.status(Response.Status.OK).entity(samlOauthInfo.asJSON()).build();
    }
}
