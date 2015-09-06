package org.picketlink.identity.federation.bindings.tomcat.idp;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * Debug Valve on the IDP end that will inform whether the SP is sending the SAMLRequest or not properly
 *
 * @author Anil.Saldhana@redhat.com
 * @since May 22, 2009
 */
public class IDPSAMLDebugValve extends ValveBase {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        StringBuilder builder = new StringBuilder();
        String param = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
        builder.append("Method = " + request.getMethod()).append("\n");
        builder.append("SAMLRequest=" + param).append("\n");
        builder.append("SAMLResponse=" + request.getParameter(GeneralConstants.SAML_RESPONSE_KEY)).append("\n");
        builder.append("Parameter exists?=" + param != null).append("\n");
        String debugInfo = builder.toString();

        logger.debug("SP Sent::" + debugInfo);

        getNext().invoke(request, response);
    }
}
