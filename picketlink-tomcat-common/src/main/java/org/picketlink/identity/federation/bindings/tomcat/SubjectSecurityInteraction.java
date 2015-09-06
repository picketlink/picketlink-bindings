package org.picketlink.identity.federation.bindings.tomcat;

import javax.security.auth.Subject;
import java.security.Principal;

/**
 * Interface to retrieve a subject
 *
 * @author Anil.Saldhana@redhat.com
 * @since Sep 13, 2011
 */
public interface SubjectSecurityInteraction {

    /**
     * Obtain a subject based on implementation
     *
     * @return
     */
    Subject get();

    /**
     * Clean up the {@link Principal} from the security cache
     *
     * @param principal
     *
     * @return
     */
    boolean cleanup(Principal principal);

    /**
     * <p>Sets the security domain name</p>
     *
     * @param securityDomain
     */
    void setSecurityDomain(String securityDomain);
}
