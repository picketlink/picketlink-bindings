package org.picketlink.identity.federation.bindings.wildfly.idp;

import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of {@link java.security.Principal} that stores the current principal
 * name and a {@link java.util.List} of roles
 *
 * @author Anil Saldhana
 * @since December 19, 2013
 */
public class PicketLinkUndertowPrincipal implements Principal,Serializable {
    private static final long serialVersionUID = 5333209596084739156L;

    protected PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    protected String name = null;

    protected List<String> roles = new ArrayList<String>();


    public PicketLinkUndertowPrincipal(String name, List<String> roles) {
        this.name = name;
        if (roles == null) {
            throw logger.nullArgumentError("roles");
        }
        this.roles.addAll(roles);
    }

    @Override
    public String getName() {
        return name;
    }

    public List<String> getRoles(){
        return Collections.unmodifiableList(roles);
    }
}
