package org.picketlink.test.identity.federation.bindings.servlets;

import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Jan 28, 2009
 */
@SuppressWarnings({ "rawtypes" })
public class TestServletConfig implements ServletConfig {
    private ServletContext sc;

    public TestServletConfig(ServletContext sc) {
        this.sc = sc;
    }

    public String getInitParameter(String name) {
        return sc.getInitParameter(name);
    }

    public Enumeration getInitParameterNames() {
        return null;
    }

    public ServletContext getServletContext() {
        return sc;
    }

    public String getServletName() {
        return null;
    }
}
