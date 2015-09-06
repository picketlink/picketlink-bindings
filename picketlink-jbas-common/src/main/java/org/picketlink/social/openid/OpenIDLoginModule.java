package org.picketlink.social.openid;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.List;

/**
 * A {@link javax.security.auth.spi.LoginModule} for JBoss environment to support OpenID
 *
 * @author Anil Saldhana
 * @since May 19, 2011
 */
public class OpenIDLoginModule extends UsernamePasswordLoginModule {

    @Override
    protected Principal getIdentity() {
        return OpenIDProcessor.cachedPrincipal.get();
    }

    @Override
    protected String getUsersPassword() throws LoginException {
        return OpenIDProcessor.EMPTY_PASSWORD;
    }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group group = new SimpleGroup("Roles");

        List<String> roles = OpenIDProcessor.cachedRoles.get();

        if (roles != null) {
            for (String role : roles) {
                group.addMember(new SimplePrincipal(role));
            }
        }
        return new Group[]{group};
    }
}
