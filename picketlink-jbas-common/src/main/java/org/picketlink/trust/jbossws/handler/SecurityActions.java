package org.picketlink.trust.jbossws.handler;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkGroup;

import javax.security.auth.Subject;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.List;

/**
 * Privileged actions.
 *
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @author Anil Saldhana
 * @version $Revision: 1 $
 */
class SecurityActions {

    static SecurityContext createSecurityContext(final Principal p, final Object cred, final Subject subject) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>() {
                public SecurityContext run() {
                    SecurityContext sc = null;
                    try {
                        sc = SecurityContextFactory.createSecurityContext(p, cred, subject, "SAML2_HANDLER");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return sc;
                }
            });
        } else {
            SecurityContext sc = null;
            try {
                sc = SecurityContextFactory.createSecurityContext(p, cred, subject, "SAML2_HANDLER");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return sc;
        }
    }

    static void setSecurityContext(final SecurityContext sc) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                public Object run() {
                    SecurityContextAssociation.setSecurityContext(sc);
                    return null;
                }
            });
        } else {
            SecurityContextAssociation.setSecurityContext(sc);
        }
    }

    static SecurityContext getSecurityContext() {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>() {
                public SecurityContext run() {
                    return SecurityContextAssociation.getSecurityContext();
                }
            });
        } else {
            return SecurityContextAssociation.getSecurityContext();
        }
    }

    /**
     * Get the {@link Subject} from the {@link SecurityContextAssociation}
     *
     * @return authenticated subject or null
     */
    static Subject getAuthenticatedSubject() {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Subject>() {
                public Subject run() {
                    SecurityContext sc = SecurityContextAssociation.getSecurityContext();
                    if (sc != null) {
                        return sc.getUtil().getSubject();
                    }
                    return null;
                }
            });
        } else {
            SecurityContext sc = SecurityContextAssociation.getSecurityContext();
            if (sc != null) {
                return sc.getUtil().getSubject();
            }
            return null;
        }
    }

    /**
     * <p>Returns a system property value using the specified <code>key</code>. If not found the <code>defaultValue</code> will be
     * returned.</p>
     *
     * @param key
     * @param defaultValue
     *
     * @return
     */
    static String getSystemProperty(final String key, final String defaultValue) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty(key, defaultValue);
                }
            });
        } else {
            return System.getProperty(key, defaultValue);
        }
    }

    static ClassLoader getClassLoader(final Class<?> clazz) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return clazz.getClassLoader();
                }
            });
        } else {
            return clazz.getClassLoader();
        }
    }

    static ClassLoader getContextClassLoader() {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            });
        } else {
            return Thread.currentThread().getContextClassLoader();
        }
    }

    /**
     * Given a {@link List} of role names, construct a group principal of type {@link Group}
     *
     * @param roles
     *
     * @return
     */
    static Group group(final List<String> roles) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Group>() {
                public Group run() {
                    Group theGroup = new PicketLinkGroup(SecurityConstants.ROLES_IDENTIFIER);
                    for (String role : roles) {
                        theGroup.addMember(new SimplePrincipal(role));
                    }
                    return theGroup;
                }
            });
        } else {
            Group theGroup = new PicketLinkGroup(SecurityConstants.ROLES_IDENTIFIER);
            for (String role : roles) {
                theGroup.addMember(new SimplePrincipal(role));
            }
            return theGroup;
        }
    }
}
