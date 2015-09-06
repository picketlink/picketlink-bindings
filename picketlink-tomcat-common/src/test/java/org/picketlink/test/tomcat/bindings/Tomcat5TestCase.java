package org.picketlink.test.tomcat.bindings;

import junit.framework.TestCase;

import org.picketlink.test.tomcat.helpers.Tomcat5Embedded;

/**
 * Tomcat5 Embedded
 *
 * @author Anil.Saldhana@redhat.com
 * @since Nov 1, 2008
 */
public class Tomcat5TestCase extends TestCase {
    boolean enable = false;

    public void testTomcat5() throws Exception {
        if (enable) {
            Tomcat5Embedded emb = new Tomcat5Embedded();
            emb.setHomePath("target/tomcat");
            emb.startServer();
            Thread.sleep(2000);
            assertTrue("Tomcat5 started", emb.hasStarted());

            // emb.createContext("target/../identity-samples/samples/employee/target/employee.war");

            emb.stopServer();
            Thread.sleep(1000);
            assertTrue(emb.hasStopped());
        }
    }
}
