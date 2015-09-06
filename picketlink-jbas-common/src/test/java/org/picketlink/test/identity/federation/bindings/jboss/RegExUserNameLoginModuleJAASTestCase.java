package org.picketlink.test.identity.federation.bindings.jboss;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.AppCallbackHandler;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.jboss.security.auth.spi.BaseCertLoginModule;
import org.jboss.security.auth.spi.CertRolesLoginModule;
import org.jboss.security.auth.spi.UsersRolesLoginModule;
import org.junit.Before;
import org.junit.Test;
import org.picketlink.identity.federation.bindings.jboss.auth.RegExUserNameLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

/**
 * Unit test the {@link org.picketlink.identity.federation.bindings.jboss.auth.RegExUserNameLoginModule}
 * stacked with a {@link CertRolesLoginModule}
 * @author Anil Saldhana
 * @since April 02, 2014
 */
public class RegExUserNameLoginModuleJAASTestCase {
    /**
     * Set up the login modules
     * @throws Exception
     */
    @Before
    public void setup() throws Exception{
        Configuration.setConfiguration(new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

                //First entry is for CertRolesLoginModule
                Map<String,Object> firstOptions = new HashMap<String, Object>();
                firstOptions.put("password-stacking", "useFirstPass");
                firstOptions.put("verifier", "org.jboss.security.auth.certs.AnyCertVerifier");
                AppConfigurationEntry firstEntry = new AppConfigurationEntry(MyCertLoginModule.class.getName(),
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,firstOptions);

                //Second entry is for RegExUserNameLoginModule
                Map<String,Object> secondOptions = new HashMap<String, Object>();
                secondOptions.put("password-stacking", "useFirstPass");
                secondOptions.put("regex", "CN=([^\",]+|\"[^\"]*\"),");
                AppConfigurationEntry secondEntry = new AppConfigurationEntry(RegExUserNameLoginModule.class.getName(),
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,secondOptions);

                //Third entry is for UsersRolesLoginModule
                Map<String,Object> thirdOptions = new HashMap<String, Object>();
                thirdOptions.put("password-stacking", "useFirstPass");
                AppConfigurationEntry thirdEntry = new AppConfigurationEntry(UsersRolesLoginModule.class.getName(),
                        AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,thirdOptions);

                return new AppConfigurationEntry[]{firstEntry,secondEntry,thirdEntry};
            }
        });
    }

    @Test
    public void validateStacking() throws Exception {
        Subject subject = new Subject();
        LoginContext loginContext = new LoginContext("dummy", subject,
                new AppCallbackHandler("CN=anil,ou=jboss,o=redhat","".toCharArray()));
        loginContext.login();
        Set<Principal> principalSet = subject.getPrincipals();
        Iterator<Principal> iterator = principalSet.iterator();
        Group groupPrincipal = null;
        while(iterator.hasNext()) {
            Principal principal = iterator.next();
            if(principal instanceof Group && principal.getName().equalsIgnoreCase("Roles")){
                groupPrincipal  = (Group) principal;
                break;
            }
        }
        assertNotNull(groupPrincipal);
        assertTrue(groupPrincipal.isMember(new SimplePrincipal("admin")));
    }

    public static class MyCertLoginModule extends AbstractServerLoginModule{
        private String name = "CN=anil,ou=jboss,o=redhat";

        public MyCertLoginModule(){
        }
        @Override
        public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
            super.initialize(subject,callbackHandler,sharedState,options);
        }

        @Override
        public boolean login() throws LoginException {
            super.loginOk = true;
            this.sharedState.put("javax.security.auth.login.name", name);
            this.sharedState.put("javax.security.auth.login.password", "dummy");
            return true;
        }

        @Override
        protected Principal getIdentity() {
            return new SimplePrincipal(name);
        }

        @Override
        protected Group[] getRoleSets() throws LoginException {
            return new Group[0];
        }
    }
}
