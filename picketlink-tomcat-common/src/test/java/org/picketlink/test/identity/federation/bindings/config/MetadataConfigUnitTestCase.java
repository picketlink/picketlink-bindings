package org.picketlink.test.identity.federation.bindings.config;

import java.io.InputStream;
import java.util.List;

import junit.framework.TestCase;

import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.KeyValueType;
import org.picketlink.config.federation.MetadataProviderType;
import org.picketlink.config.federation.TrustType;
import org.picketlink.config.federation.parsers.SAMLConfigParser;

/**
 * Config for the SAMLv2 Metadata Profile
 *
 * @author Anil.Saldhana@redhat.com
 * @since Apr 22, 2009
 */
public class MetadataConfigUnitTestCase extends TestCase {
    String config = "config/test-metadata-config-";

    public void testMetadata() throws Exception {
        Object object = this.unmarshall(config + "1.xml");
        assertNotNull("IDP is not null", object);
        IDPType idp = (IDPType) object;
        assertEquals("somefqn", idp.getRoleGenerator());

        TrustType trust = idp.getTrust();
        assertNotNull("Trust is not null", trust);
        String domains = trust.getDomains();
        assertTrue("localhost trusted", domains.indexOf("localhost") > -1);
        assertTrue("jboss.com trusted", domains.indexOf("jboss.com") > -1);

        MetadataProviderType metaDataProvider = idp.getMetaDataProvider();
        assertNotNull("MetadataProvider is not null", metaDataProvider);
        assertEquals("org.jboss.test.somefqn", metaDataProvider.getClassName());

        List<KeyValueType> keyValues = metaDataProvider.getOption();
        assertTrue(1 == keyValues.size());
        KeyValueType kvt = keyValues.get(0);
        assertEquals("FileName", kvt.getKey());
        assertEquals("myfile", kvt.getValue());
    }

    private Object unmarshall(String configFile) throws Exception {
        // String schema = PicketLinkFederationConstants.SCHEMA_IDFED;

        ClassLoader tcl = Thread.currentThread().getContextClassLoader();
        InputStream is = tcl.getResourceAsStream(configFile);
        assertNotNull("Inputstream not null", is);

        return (new SAMLConfigParser()).parse(is);
    }
}
