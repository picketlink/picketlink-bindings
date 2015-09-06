package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.realm.GenericPrincipal;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;

import java.security.Principal;
import java.util.List;

/**
 * Common code useful for a SP
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 9, 2009
 */
public class SPUtil {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /**
     * Create a SAML2 auth request
     *
     * @param serviceURL URL of the service
     * @param identityURL URL of the identity provider
     *
     * @return
     *
     * @throws ConfigurationException
     */
    public AuthnRequestType createSAMLRequest(String serviceURL, String identityURL) throws ConfigurationException {
        if (serviceURL == null) {
            throw logger.nullArgumentError("serviceURL");
        }
        if (identityURL == null) {
            throw logger.nullArgumentError("identityURL");
        }

        SAML2Request saml2Request = new SAML2Request();
        String id = IDGenerator.create("ID_");
        return saml2Request.createAuthnRequestType(id, serviceURL, identityURL, serviceURL);
    }

    /**
     * Create an instance of the {@link GenericPrincipal}
     *
     * @param request
     * @param username
     * @param roles
     *
     * @return
     */
    public Principal createGenericPrincipal(Request request, String username, List<String> roles) {
        Context ctx = request.getContext();
        return new GenericPrincipal(ctx.getRealm(), username, null, roles);
    }
}
