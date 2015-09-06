package org.picketlink.trust.jbossws.handler;

import org.apache.cxf.phase.PhaseInterceptorChain;
import org.apache.cxf.security.SecurityContext;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;

import javax.security.auth.Subject;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;

/**
 * <p>implementation for {@link AbstractSAML2Handler} specific for the JBoss AS7 binding.</p>
 *
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @author <a href="alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author Anil Saldhana
 * @version $Revision: 1 $
 */
public class SAML2Handler extends AbstractSAML2Handler {

    /* (non-Javadoc)
     * @see org.picketlink.trust.jbossws.handler.AbstractSAML2Handler#propagateSubject(org.picketlink.identity.federation.core.wstrust.SamlCredential, javax.security.auth.Subject, java.security.Principal)
     */
    @Override
    protected void createSecurityContext(SamlCredential credential, final Subject theSubject, final Principal principal) {
        super.createSecurityContext(credential, theSubject, principal);
        org.apache.cxf.security.SecurityContext secContext = createCXFSecurityContext(theSubject, principal);

        if (PhaseInterceptorChain.getCurrentMessage() != null) {
            PhaseInterceptorChain.getCurrentMessage().put(org.apache.cxf.security.SecurityContext.class, secContext);
        }
    }

    /**
     * <p>Creates an instance of {@link SecurityContext}.</p>
     *
     * @param theSubject
     * @param principal
     *
     * @return
     */
    private SecurityContext createCXFSecurityContext(final Subject theSubject, final Principal principal) {
        return new org.apache.cxf.security.SecurityContext() {

            public boolean isUserInRole(String role) {
                if (theSubject == null || theSubject.getPrincipals().size() <= 1) {
                    return false;
                }
                for (Principal principal : theSubject.getPrincipals()) {
                    if (principal instanceof Group && checkGroup((Group) principal, role)) {
                        return true;
                    }
                }
                return false;
            }

            public Principal getUserPrincipal() {
                return principal;
            }
        };
    }

    protected boolean checkGroup(Group group, String role) {
        if (group.getName().equals(role)) {
            return true;
        }

        for (Enumeration<? extends Principal> members = group.members(); members.hasMoreElements(); ) {
            // this might be a plain role but could represent a group consisting of other groups/roles
            Principal member = members.nextElement();
            if (member.getName().equals(role) || member instanceof Group && checkGroup((Group) member, role)) {
                return true;
            }
        }
        return false;
    }
}
