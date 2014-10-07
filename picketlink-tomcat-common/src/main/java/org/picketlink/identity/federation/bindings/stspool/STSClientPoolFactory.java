/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.identity.federation.bindings.stspool;

import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig;
import org.picketlink.identity.federation.core.wstrust.STSClientCreationCallBack;
import org.picketlink.identity.federation.core.wstrust.STSClientPool;
import org.picketlink.identity.federation.core.wstrust.STSClientFactory;


/**
 * Simple factory for creating {@link STSClient}s.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class STSClientPoolFactory implements STSClientPool {

    private STSClientPoolInternal stsClientPoolInternal;

    private STSClientPoolFactory() {
        stsClientPoolInternal = new STSClientPoolInternal();
    }

    private static class LazySTSClientFactory {
        private static final STSClientPoolFactory INSTANCE = new STSClientPoolFactory();
    }

    /**
     * Get instance of {@link STSClientPool}.
     *
     * @return {@link STSClientPool} instance
     */
    public static STSClientPool getPoolInstance() {
        STSClientPoolFactory cf = LazySTSClientFactory.INSTANCE;
        STSClientFactory.setInstance(cf);
        return cf;
    }

    /**
     * This method initializes sub pool of clients by given configuration data and returns client from that pool.
     *
     * When pooling is disabled it does nothing.
     *
     * @param config to construct the pool of clients
     */
    public void createPool(final STSClientConfig config) {
        createPool(STSClientPoolInternal.DEFAULT_NUM_STS_CLIENTS, config);
    }

    /**
     * This method initializes sub pool of clients by given configuration data and returns client from that pool.
     * initialNumberOfClients is used to initialize the pool for the given number of clients.
     *
     * When pooling is disabled it does nothing.
     *
     * @param initialNumberOfClients initial number of clients in the pool
     * @param config to construct the pool of clients
     */
    public void createPool(int initialNumberOfClients, final STSClientConfig config) {
        stsClientPoolInternal.initialize(initialNumberOfClients, config);
    }

    /**
     * This method initializes sub pool of clients by given configuration data.
     * initialNumberOfClients is used to initialize the pool for the given number of clients.
     *
     * When pooling is disabled it does nothing.
     *
     * @param initialNumberOfClients initial number of clients in the pool
     * @param callBack which provide configuration
     */

    public void createPool(int initialNumberOfClients, final STSClientCreationCallBack callBack) {
        stsClientPoolInternal.initialize(initialNumberOfClients, callBack);
    }

    /**
     * Destroys client sub pool denoted by given config.
     *
     * @param config {@link STSClientConfiguration} to find client sub pool to destroy
     */
    public void destroyPool(final STSClientConfig config) {
        stsClientPoolInternal.destroy(config);
    }


   /**
    * Destroy all the pools attached to given module name.
    *
    * @param moduleName module name to destroy pools or "" or null to destroy default module's pools.
    */
    public void destroyPool(final String moduleName) {
        stsClientPoolInternal.destroy(moduleName);
    }

    /**
     * Returns given {@link STSClient} back to the sub pool of clients.
     * Sub pool is determined automatically from client configuration.
     *
     * @param {@link STSClient} to return back to the sub pool of clients
     */
    public void returnClient(final STSClient stsClient) {
        stsClientPoolInternal.putIn(stsClient);
    }

    /**
     * Get STSClient from sub pool denoted by config.
     * @param config {@link STSClientConfiguration} to find client sub pool
     * @return {@link STSClient} from the sub pool of clients
     */
    public STSClient getClient(final STSClientConfig config) {
        STSClient client = stsClientPoolInternal.takeOut(config);
        if (client == null) {
            // non pooled client
            return new STSClient(config);
        }
        return client;
    }

    /**
     * Checks whether given config has already sub pool of clients created.
     *
     * @param config {@link STSClientConfiguration} to find client sub pool
     * @return true if config was already used as sub pool key
     */
    public boolean configExists(final STSClientConfig config) {
        return stsClientPoolInternal.isConfigInitialized(config);
    }

}
