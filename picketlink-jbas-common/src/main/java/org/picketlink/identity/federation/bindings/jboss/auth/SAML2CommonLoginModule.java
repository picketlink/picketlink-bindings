package org.picketlink.identity.federation.bindings.jboss.auth;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.List;
import java.util.Map;

/**
 * Login Module that is capable of dealing with SAML2 cases <p> The password sent to this module should be {@link
 * ServiceProviderSAMLContext#EMPTY_PASSWORD} </p> <p> The username is available from {@link
 * ServiceProviderSAMLContext#getUserName()} and roles is available from {@link ServiceProviderSAMLContext#getRoles()}. If the roles
 * is null, then plugged in login modules in the stack have to provide the roles. </p>
 *
 * @author Anil.Saldhana@redhat.com
 * @since Feb 13, 2009
 */
public abstract class SAML2CommonLoginModule extends UsernamePasswordLoginModule {

    protected String groupName = "Roles";

    /*
     * (non-Javadoc)
     *
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#initialize(javax.security.auth.Subject,
     * javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        String groupNameStr = (String) options.get("groupPrincipalName");
        if (StringUtil.isNotNull(groupNameStr)) {
            groupName = groupNameStr.trim();
        }
    }

    @Override
    protected Principal getIdentity() {
        return new SimplePrincipal(ServiceProviderSAMLContext.getUserName());
    }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        Group group = new SimpleGroup(groupName);

        List<String> roles = ServiceProviderSAMLContext.getRoles();
        if (roles != null) {
            for (String role : roles) {
                group.addMember(new SimplePrincipal(role));
            }
        }
        return new Group[]{group};
    }

    @Override
    protected String getUsersPassword() throws LoginException {
        return ServiceProviderSAMLContext.EMPTY_PASSWORD;
    }
}
