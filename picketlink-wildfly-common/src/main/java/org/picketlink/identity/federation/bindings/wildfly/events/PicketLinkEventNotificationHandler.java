package org.picketlink.identity.federation.bindings.wildfly.events;

/**
 * Interface for handling {@link PicketLinkEventNotification}
 * @author Anil Saldhana
 * @since November 04, 2013
 */
public interface PicketLinkEventNotificationHandler {
    /**
     * Handle the {@link PicketLinkEventNotification}
     * @param eventNotification the {@link PicketLinkEventNotification} that is sent
     */
    void handle(PicketLinkEventNotification eventNotification);
}
