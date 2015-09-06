package org.picketlink.identity.federation.bindings.jboss.auth;

/**
 * Login Module that is capable of dealing with SAML2 cases <p> The password sent to this module should be {@link
 * org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext#EMPTY_PASSWORD} </p> <p> The username is available from {@link
 * org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext#getUserName()} and roles is available
 * from {@link org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext#getRoles()}. If the roles
 * is null, then plugged in login modules in the stack have to provide the roles. </p>
 *
 * @author Anil.Saldhana@redhat.com
 * @since Feb 13, 2009
 */
public class SAML2LoginModule extends SAML2CommonLoginModule {

}
