package org.picketlink.identity.federation.bindings.tomcat.sp.plugins;

import org.picketlink.identity.federation.bindings.tomcat.sp.AbstractAccountChooserValve;

import javax.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Implementation of {@link org.picketlink.identity.federation.bindings.tomcat.sp.AbstractAccountChooserValve.AccountIDPMapProvider}
 * using a properties file
 *
 * @author Anil Saldhana
 * @since January 23, 2014
 */
public class PropertiesAccountMapProvider implements AbstractAccountChooserValve.AccountIDPMapProvider {

    private ClassLoader classLoader = null;

    private ServletContext servletContext = null;

    public static final String PROP_FILE_NAME = "idpmap.properties";

    public static final String WEB_INF_PROP_FILE_NAME = "/WEB-INF/idpmap.properties";

    @Override
    public void setClassLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    @Override
    public Map<String, String> getIDPMap() throws IOException {
        Map<String, String> idpmap = new HashMap<String, String>();

        InputStream inputStream = null;

        Properties properties = new Properties();
        if (classLoader != null) {
            inputStream = classLoader.getResourceAsStream(PROP_FILE_NAME);
        }
        if (inputStream == null && servletContext != null) {
            inputStream = servletContext.getResourceAsStream(PROP_FILE_NAME);
        }
        if (inputStream == null && servletContext != null) {
            inputStream = servletContext.getResourceAsStream(WEB_INF_PROP_FILE_NAME);
        }
        if (inputStream == null) {
            inputStream = getClass().getResourceAsStream(PROP_FILE_NAME);
        }
        if (inputStream != null) {
            properties.load(inputStream);
            if (properties != null) {
                Set<Object> keyset = properties.keySet();
                for (Object key : keyset) {
                    idpmap.put((String) key, (String) properties.get(key));
                }
            }
        }
        return idpmap;
    }
}
