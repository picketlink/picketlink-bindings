package org.picketlink.social.openid;

import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.log4j.Logger;
import org.picketlink.common.util.StringUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * Tomcat Authenticator that provides OpenID based authentication
 *
 * @author Anil Saldhana
 * @since Sep 17, 2011
 */
public class OpenIDConsumerAuthenticator extends FormAuthenticator {

    protected static Logger log = Logger.getLogger(OpenIDConsumerAuthenticator.class);
    protected boolean trace = log.isTraceEnabled();

    private enum STATES {
        AUTH,
        AUTHZ,
        FINISH
    }

    ;

    public static ThreadLocal<Principal> cachedPrincipal = new ThreadLocal<Principal>();

    public static ThreadLocal<List<String>> cachedRoles = new ThreadLocal<List<String>>();
    public static String EMPTY_PASSWORD = "EMPTY";

    private String returnURL = null;

    private String requiredAttributes = "name,email,ax_firstName,ax_lastName,ax_fullName,ax_email";

    private String optionalAttributes = null;

    protected List<String> roles = new ArrayList<String>();

    // Whether the authenticator has to to save and restore request
    protected boolean saveRestoreRequest = true;

    protected OpenIDProcessor processor = null;

    // Incompatibilities in register() method across JBossWeb versions
    private Method theSuperRegisterMethod = null;

    public void setReturnURL(String returnURL) {
        this.returnURL = StringUtil.getSystemPropertyAsString(returnURL);
    }

    public void setRequiredAttributes(String requiredAttributes) {
        this.requiredAttributes = requiredAttributes;
    }

    public void setOptionalAttributes(String optionalAttributes) {
        this.optionalAttributes = optionalAttributes;
    }

    public void setSaveRestoreRequest(boolean saveRestoreRequest) {
        this.saveRestoreRequest = saveRestoreRequest;
    }

    /**
     * A comma separated string that represents the roles the web app needs to pass authorization
     *
     * @param roleStr
     */
    public void setRoleString(String roleStr) {
        if (roleStr == null) {
            throw new RuntimeException("Role String is null in configuration");
        }
        List<String> tokens = StringUtil.tokenize(roleStr);
        for (String token : tokens) {
            roles.add(token);
        }
    }

    public boolean authenticate(HttpServletRequest request, HttpServletResponse response, LoginConfig loginConfig)
        throws IOException {
        if (request instanceof Request == false) {
            throw new IOException("Not of type Catalina request");
        }
        if (response instanceof Response == false) {
            throw new IOException("Not of type Catalina response");
        }
        return authenticate((Request) request, (Response) response, loginConfig);
    }

    /**
     * Authenticate the request
     *
     * @param request
     * @param response
     * @param config
     *
     * @return
     *
     * @throws java.io.IOException
     * @throws {@link              RuntimeException} when the response is not of type catalina response object
     */
    public boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
        if (response instanceof Response) {
            Response catalinaResponse = (Response) response;
            return authenticate(request, catalinaResponse, config);
        }
        throw new RuntimeException("Wrong type of response:" + response);
    }

    public boolean authenticate(Request request, Response response, LoginConfig loginConfig) throws IOException {
        if (processor == null) {
            processor = new OpenIDProcessor(returnURL, requiredAttributes, optionalAttributes);
        }

        Principal userPrincipal = request.getUserPrincipal();
        if (userPrincipal != null) {
            if (trace) {
                log.trace("Logged in as:" + userPrincipal);
            }
            return true;
        }

        if (!processor.isInitialized()) {
            try {
                processor.initialize(roles);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        HttpSession httpSession = request.getSession();
        String state = (String) httpSession.getAttribute("STATE");
        if (trace) {
            log.trace("state=" + state);
        }

        if (STATES.FINISH.name().equals(state)) {
            return true;
        }

        if (state == null || state.isEmpty()) {
            return processor.prepareAndSendAuthRequest(request, response);
        }
        // We have sent an auth request
        if (state.equals(STATES.AUTH.name())) {
            Session session = request.getSessionInternal(true);
            if (saveRestoreRequest) {
                this.saveRequest(request, session);
            }

            Principal principal = processor.processIncomingAuthResult(request, response, context.getRealm());
            if (principal == null) {
                throw new RuntimeException("Principal was null. Maybe login modules need to be configured properly.");
            }
            String principalName = principal.getName();
            request.getSessionInternal().setNote(Constants.SESS_USERNAME_NOTE, principalName);
            request.getSessionInternal().setNote(Constants.SESS_PASSWORD_NOTE, "");
            request.setUserPrincipal(principal);

            if (saveRestoreRequest) {
                this.restoreRequest(request, request.getSessionInternal());
            }

            if (trace) {
                log.trace("Logged in as:" + principal);
            }

            registerWithAuthenticatorBase(request, response, principal, principalName);

            request.getSession().setAttribute("STATE", STATES.FINISH.name());
            return true;
        }
        return false;
    }

    protected void registerWithAuthenticatorBase(Request request, Response response, Principal principal, String userName) {
        try {
            register(request, response, principal, Constants.FORM_METHOD, userName, "");
        } catch (NoSuchMethodError nse) {
            if (theSuperRegisterMethod == null) {
                Class<?>[] args = new Class[]{Request.class, HttpServletResponse.class, Principal.class, String.class,
                    String.class, String.class};
                Class<?> superClass = getClass().getSuperclass();
                theSuperRegisterMethod = SecurityActions.getMethod(superClass, "register", args);
            }
            if (theSuperRegisterMethod != null) {
                Object[] objectArgs = new Object[]{request, response.getResponse(), principal, Constants.FORM_METHOD,
                    userName, OpenIDProcessor.EMPTY_PASSWORD};
                try {
                    theSuperRegisterMethod.invoke(this, objectArgs);
                } catch (Exception e) {
                    log.error("Unable to register:", e);
                }
            }
        }
    }
}
