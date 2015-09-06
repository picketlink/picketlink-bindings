package org.picketlink.identity.federation.bindings.tomcat.sp;

import org.apache.catalina.Context;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.util.LifecycleSupport;
import org.apache.catalina.valves.ValveBase;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.bindings.tomcat.sp.plugins.PropertiesAccountMapProvider;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PLINK-344: Account Chooser At the Service Provider to enable redirection to the appropriate IDP
 *
 * @author Anil Saldhana
 * @since January 21, 2014
 */
public abstract class AbstractAccountChooserValve extends ValveBase implements Lifecycle {
    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    public static final String ACCOUNT_CHOOSER_COOKIE_NAME = "picketlink.account.name";

    public static final String ACCOUNT_PARAMETER = "idp";

    public static final String AUTHENTICATING = "AUTHENTICATING";

    public static final String STATE = "STATE";

    /**
     * Domain Name to be used in the cookie that is sent out
     */
    protected String domainName;

    protected String accountChooserPage = "/accountChooser.html";

    protected ConcurrentHashMap<String, String> idpMap = new ConcurrentHashMap<String, String>();

    private String accountIDPMapProviderName = PropertiesAccountMapProvider.class.getName();
    protected AccountIDPMapProvider accountIDPMapProvider;

    /**
     * Sets the account chooser cookie expiry. By default, we choose -1 which means
     * cookie exists for the remainder of the browser session.
     */
    protected int cookieExpiry = -1;

    /**
     * The lifecycle event support for this component.
     */
    protected LifecycleSupport lifecycle = new LifecycleSupport(this);

    @Override
    public void start() throws LifecycleException {
        try {
            Class<?> clazz = SecurityActions.loadClass(getClass(), this.accountIDPMapProviderName);

            if (clazz == null) {
                throw logger.classNotLoadedError(this.accountIDPMapProviderName);
            }

            accountIDPMapProvider = (AccountIDPMapProvider) clazz.newInstance();

            Context context = (Context) getContainer();
            accountIDPMapProvider.setServletContext(context.getServletContext());
            idpMap.putAll(accountIDPMapProvider.getIDPMap());
        } catch (Exception e) {
            throw new LifecycleException("Could not start " + getClass().getName() + ".", e);
        }
    }

    @Override
    public void stop() throws LifecycleException {

    }

    @Override
    public void removeLifecycleListener(LifecycleListener listener) {
        lifecycle.removeLifecycleListener(listener);
    }

    @Override
    public LifecycleListener[] findLifecycleListeners() {
        return lifecycle.findLifecycleListeners();
    }

    @Override
    public void addLifecycleListener(LifecycleListener listener) {
        lifecycle.addLifecycleListener(listener);
    }

    /**
     * Set the domain name for the cookie to be sent to the browser
     * There is no default.
     *
     * Setting the domain name for the cookie is optional.
     *
     * @param domainName
     */
    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    /**
     * Set the cookie expiry in seconds.
     * Default value is -1
     * @param value
     */
    public void setCookieExpiry(String value){
        try{
            int expiry = Integer.parseInt(value);
            cookieExpiry = expiry;
        }catch(NumberFormatException nfe){
            logger.processingError(nfe);
        }
    }
    /**
     * Set the fully qualified name of the implementation of
     * {@link org.picketlink.identity.federation.bindings.tomcat.sp.AbstractAccountChooserValve.AccountIDPMapProvider}
     *
     * Default: {@link org.picketlink.identity.federation.bindings.tomcat.sp.plugins.PropertiesAccountMapProvider}
     * @param idpMapProviderName
     */
    public void setAccountIDPMapProvider(String idpMapProviderName){
        this.accountIDPMapProviderName = idpMapProviderName;
    }

    /**
     * Set the name of the html or jsp page that has the accounts for the
     * user to choose.
     * Default: "/accountChooser.html" is used
     *
     * @param pageName
     */
    public void setAccountChooserPage(String pageName) {
        this.accountChooserPage = pageName;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        Session session = request.getSessionInternal();

        if(idpMap.isEmpty()){
            idpMap.putAll(accountIDPMapProvider.getIDPMap());
        }

        String sessionState = (String) session.getNote(STATE);

        String idpChosenKey = request.getParameter(ACCOUNT_PARAMETER);
        String cookieValue = cookieValue(request);
        if (cookieValue != null || AUTHENTICATING.equals(sessionState)) {
            if(idpChosenKey != null){
                String chosenIDP = idpMap.get(idpChosenKey);
                request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
            }

            // Case when user is directed to IDP and wants to change the IDP. So he enters the URL again
            if (AUTHENTICATING.equals(sessionState) && request.getParameter(GeneralConstants.SAML_RESPONSE_KEY) == null) {
                session.removeNote(STATE);
                redirectToChosenPage(accountChooserPage, request, response);
                return;
            }
            proceedToAuthentication(request, response, cookieValue);
        } else {
            if (idpChosenKey != null) {
                String chosenIDP = idpMap.get(idpChosenKey);
                if (chosenIDP != null) {
                    request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
                    session.setNote(STATE, AUTHENTICATING);
                    proceedToAuthentication(request, response, idpChosenKey);
                }else {
                    logger.configurationFileMissing(":IDP Mapping");
                    throw new ServletException();
                }
            } else {
                // redirect to provided html
                //saveRequest(request, request.getSessionInternal());
                redirectToChosenPage(accountChooserPage,request,response);
                return;
            }
        }
    }

    /**
     * Proceed to the Service Provider Authentication Mechanism
     * @param request
     * @param response
     * @param cookieValue
     * @throws IOException
     * @throws ServletException
     */
    protected void proceedToAuthentication(Request request, Response response, String cookieValue) throws IOException,
        ServletException {
        Session session = request.getSessionInternal(false);
        try {
            /*String sessionState = (String) session.getNote(STATE);
            // Case when user is directed to IDP and wants to change the IDP. So he enters the URL again
            if (AUTHENTICATING.equals(sessionState) && request.getParameter(GeneralConstants.SAML_RESPONSE_KEY) == null) {
                session.removeNote(STATE);
                redirectToChosenPage(accountConfirmationPage, request, response);
                return;
            }*/
            getNext().invoke(request, response);
        } finally {
            String state = session != null ? (String) session.getNote(STATE) : null;

            //If we are authenticated and registered at the service provider
            if (request.getUserPrincipal() != null && StringUtil.isNotNull(state)) {
                session.removeNote(STATE);
                // Send back a cookie
                Context context = (Context) getContainer();
                String contextpath = context.getPath();

                if(cookieValue == null){
                    cookieValue = request.getParameter(AbstractAccountChooserValve.ACCOUNT_PARAMETER);
                }

                Cookie cookie = new Cookie(ACCOUNT_CHOOSER_COOKIE_NAME, cookieValue);
                cookie.setPath(contextpath);
                cookie.setMaxAge(cookieExpiry);
                if(domainName != null){
                    cookie.setDomain(domainName);
                }
                response.addCookie(cookie);
            }
        }
    }

    /**
     * Redirect user to a page
     * @param page
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    protected void redirectToChosenPage(String page, Request request, Response response) throws ServletException, IOException {
        Context context = (Context) getContainer();
        RequestDispatcher requestDispatcher = context.getServletContext().getRequestDispatcher(page);
        if (requestDispatcher != null) {
            requestDispatcher.forward(request.getRequest(), response);
        }
    }

    protected String cookieValue(Request request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String cookieName = cookie.getName();
                String cookieDomain = cookie.getDomain();
                if (cookieDomain != null && cookieDomain.equalsIgnoreCase(domainName)) {
                    // Found a cookie with the same domain name
                    if (ACCOUNT_CHOOSER_COOKIE_NAME.equals(cookieName)) {
                        // Found cookie
                        String cookieValue = cookie.getValue();
                        String chosenIDP = idpMap.get(cookieValue);
                        if (chosenIDP != null) {
                            request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
                            return cookieValue;
                        }
                    }
                }else{
                    if (ACCOUNT_CHOOSER_COOKIE_NAME.equals(cookieName)) {
                        // Found cookie
                        String cookieValue = cookie.getValue();
                        String chosenIDP = idpMap.get(cookieValue);
                        if (chosenIDP != null) {
                            request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
                            return cookieValue;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Save the original request information into our session.
     *
     * @param request The request to be saved
     * @param session The session to contain the saved information
     * @throws IOException
     */
    protected abstract void saveRequest(Request request, Session session) throws IOException;

    /**
     * Restore the original request from information stored in our session. If the original request is no longer present
     * (because the session timed out), return <code>false</code>; otherwise, return <code>true</code>.
     *
     * @param request The request to be restored
     * @param session The session containing the saved information
     */
    protected abstract boolean restoreRequest(Request request, Session session) throws IOException;

    /**
     * Interface for obtaining the Identity Provider Mapping
     */
    public interface AccountIDPMapProvider{
        /**
         * Set the servlet context for resources on web classpath
         * @param servletContext
         */
        void setServletContext(ServletContext servletContext);
        /**
         * Set a {@link java.lang.ClassLoader} for the Provider
         * @param classLoader
         */
        void setClassLoader(ClassLoader classLoader);
        /**
         * Get a map of AccountName versus IDP URLs
         * @return
         */
        Map<String,String> getIDPMap() throws IOException;
    }
}
