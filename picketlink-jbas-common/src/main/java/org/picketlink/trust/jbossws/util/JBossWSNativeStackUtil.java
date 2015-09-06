package org.picketlink.trust.jbossws.util;

import org.jboss.logging.Logger;

import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import java.lang.reflect.Method;

/**
 * Utility class that uses reflection on the JBossWS Native Stack as backup strategy
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jul 13, 2011
 */
public class JBossWSNativeStackUtil {

    protected static Logger log = Logger.getLogger(JBossWSNativeStackUtil.class);
    protected static boolean trace = log.isTraceEnabled();

    /**
     * It is unfortunate that the {@link MessageContext} does not contain the port name. We will use reflection on the JBoss WS
     * Native stack
     *
     * @param msgContext
     *
     * @return
     */
    public static QName getPortNameViaReflection(Class<?> callingClazz, MessageContext msgContext) {
        try {
            Class<?> clazz = SecurityActions.getClassLoader(callingClazz).loadClass(
                "org.jboss.ws.core.jaxws.handler.SOAPMessageContextJAXWS");
            Method endpointMDMethod = clazz.getMethod("getEndpointMetaData", new Class[0]);
            Object endpointMD = endpointMDMethod.invoke(msgContext, new Object[0]);

            clazz = SecurityActions.getClassLoader(callingClazz).loadClass("org.jboss.ws.metadata.umdm.EndpointMetaData");
            Method portNameMethod = clazz.getMethod("getPortName", new Class[0]);

            return (QName) portNameMethod.invoke(endpointMD, new Object[0]);
        } catch (Exception e) {
            if (trace) {
                log.trace("Exception using backup method to get port name=", e);
            }
        }
        return null;
    }
}
