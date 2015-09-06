package org.picketlink.test.identity.federation.bindings.mock;

import java.security.Principal;

import org.apache.catalina.realm.RealmBase;

/**
 * Mock Tomcat Realm
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 21, 2009
 */
public class MockCatalinaRealm extends RealmBase {
    private String name;
    private String pass;
    private Principal principal;

    public MockCatalinaRealm(String name, String pass, Principal p) {
        this.name = name;
        this.pass = pass;
        this.principal = p;
    }

    @Override
    protected String getName() {
        return name;
    }

    @Override
    protected String getPassword(String arg0) {
        return pass;
    }

    @Override
    protected Principal getPrincipal(String arg0) {
        return principal;
    }

    @Override
    public Principal authenticate(String arg0, String arg1) {
        return principal;
    }
}
