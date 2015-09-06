package org.picketlink.identity.federation.bindings.jboss.subject;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.SubjectSecurityManager;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction;
import org.picketlink.identity.federation.core.factories.JBossAuthCacheInvalidationFactory;
import org.picketlink.identity.federation.core.factories.JBossAuthCacheInvalidationFactory.TimeCacheExpiry;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import java.security.Principal;
import java.util.Calendar;

/**
 * An implementation of {@link SubjectSecurityInteraction} for JBoss AS
 *
 * @author Anil.Saldhana@redhat.com
 * @since Sep 13, 2011
 */
public class PicketLinkJBossSubjectInteraction implements SubjectSecurityInteraction {

    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /**
     * @see org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction#cleanup(java.security.Principal)
     */
    public boolean cleanup(Principal principal) {
        try {
            String securityDomain = getSecurityDomain();

            logger.trace("Determined Security Domain = " + securityDomain);

            TimeCacheExpiry cacheExpiry = JBossAuthCacheInvalidationFactory.getCacheExpiry();
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.SECOND, 10);// Add 25 seconds

            logger.trace("Will expire from cache in 10 seconds, principal = " + principal);

            cacheExpiry.register(securityDomain, calendar.getTime(), principal);
            // Additional expiry of simple principal
            cacheExpiry.register(securityDomain, calendar.getTime(), new SimplePrincipal(principal.getName()));
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

    protected String getSecurityDomain() throws NamingException {
        // Get the SecurityManagerService from JNDI
        InitialContext ctx = new InitialContext();
        SubjectSecurityManager ssm = (SubjectSecurityManager) ctx.lookup("java:comp/env/security/securityMgr");
        if (ssm == null) {
            throw logger.nullValueError("Unable to get the subject security manager");
        }
        return ssm.getSecurityDomain();
    }

    public void setSecurityDomain(String securityDomain) {

    }
}
