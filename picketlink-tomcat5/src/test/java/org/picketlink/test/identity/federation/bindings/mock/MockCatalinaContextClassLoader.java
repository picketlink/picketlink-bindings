package org.picketlink.test.identity.federation.bindings.mock;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.Map;

/**
 * Mock TCL
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 7, 2009
 */
public class MockCatalinaContextClassLoader extends URLClassLoader {
    private String profile;

    private ClassLoader delegate;

    private final Map<String, InputStream> streams = new HashMap<String, InputStream>();

    public MockCatalinaContextClassLoader(URL[] urls) {
        super(urls);
    }

    public void setDelegate(ClassLoader tcl) {
        this.delegate = tcl;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public void associate(String name, InputStream is) {
        this.streams.put(name, is);
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        if (streams.containsKey(name))
            return streams.get(name);

        if (profile == null)
            throw new RuntimeException("null profile when seeking resource:" + name);
        InputStream is = delegate.getResourceAsStream(profile + "/" + name);
        if (is == null)
            is = super.getResourceAsStream(name);
        return is;
    }
}
