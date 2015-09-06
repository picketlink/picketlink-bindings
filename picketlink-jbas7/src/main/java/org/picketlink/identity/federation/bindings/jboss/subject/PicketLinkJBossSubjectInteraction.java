package org.picketlink.identity.federation.bindings.jboss.subject;

import org.jboss.security.CacheableManager;
import org.jboss.security.SecurityConstants;
import org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import java.security.Principal;

/**
 * An implementation of {@link SubjectSecurityInteraction} for JBoss AS 7.
 *
 * @author Anil.Saldhana@redhat.com <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 * @since Sep 13, 2011
 */
public class PicketLinkJBossSubjectInteraction implements SubjectSecurityInteraction {

    private String securityDomain;

    /**
     * @see org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction#cleanup(java.security.Principal)
     */
    public boolean cleanup(Principal principal) {
        try {
            String lookupDomain = this.securityDomain;

            if (lookupDomain.startsWith(SecurityConstants.JAAS_CONTEXT_ROOT) == false) {
                lookupDomain = SecurityConstants.JAAS_CONTEXT_ROOT + "/" + lookupDomain;
            }

            // lookup the JBossCachedAuthManager.
            InitialContext context = new InitialContext();
            CacheableManager manager = (CacheableManager) context.lookup(lookupDomain);

            // Flush the Authentication Cache
            manager.flushCache(principal);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }

        return false;
    }

    /**
     * @see org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction#get()
     */
    public Subject get() {
        try {
            return (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
        } catch (PolicyContextException e) {
            throw new RuntimeException(e);
        }
    }

    public void setSecurityDomain(String securityDomain) {
        this.securityDomain = securityDomain;
    }
}
