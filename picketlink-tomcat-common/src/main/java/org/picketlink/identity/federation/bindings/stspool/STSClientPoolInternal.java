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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.bindings.util.ModuleUtils;
import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig;
import org.picketlink.identity.federation.core.wstrust.STSClientConfigKeyProvider;
import org.picketlink.identity.federation.core.wstrust.STSClientCreationCallBack;

/**
 * Simple pool of {@link STSClient} classes.
 * This class is not intended to be used directly by user code. Use {@link STSClientPoolFactory} class instead.
 *
 * @author Peter Skopek : pskopek at (redhat.com)
 *
 */
class STSClientPoolInternal {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    static int DEFAULT_NUM_STS_CLIENTS = 10;

    private Hashtable<String, ArrayList<STSClient>> free = new Hashtable<String, ArrayList<STSClient>>();
    private Hashtable<String, ArrayList<STSClient>> inUse = new Hashtable<String, ArrayList<STSClient>>();
    private Hashtable<String, STSConfigData> configs = new Hashtable<String, STSConfigData>();

    STSClientPoolInternal() {
    }

    void initialize(int numberOfSTSClients, STSClientConfig stsClientConfig) {
        internalInitialize(numberOfSTSClients, stsClientConfig, null);
    }

    void initialize(STSClientConfig stsClientConfig) {
        internalInitialize(DEFAULT_NUM_STS_CLIENTS, stsClientConfig, null);
    }


    void initialize(int numberOfSTSClients, STSClientCreationCallBack clientCreationCallBack) {
        internalInitialize(numberOfSTSClients, null, clientCreationCallBack);
    }

    private synchronized void internalInitialize(final int numberOfSTSClients, STSClientConfig stsClientConfig, STSClientCreationCallBack clientCreationCallBack) {

        if (numberOfSTSClients <= 0) {
            return;
        }


        String key = null;
        if (clientCreationCallBack != null) {
            key = substituteKey(clientCreationCallBack.getKey());
        } else {
            key = key(stsClientConfig);
        }

        if (!configs.containsKey(key)) {
            ArrayList<STSClient> clients = new ArrayList<STSClient>(numberOfSTSClients);
            if (clientCreationCallBack != null) {
                for (int i = 0; i < numberOfSTSClients; i++) {
                    clients.add(clientCreationCallBack.createClient());
                }
            } else {
                for (int i = 0; i < numberOfSTSClients; i++) {
                    clients.add(new STSClient(stsClientConfig));
                }
            }
            STSConfigData configData = new STSConfigData();
            configData.initialNumberOfClients = numberOfSTSClients;
            if (clientCreationCallBack != null) {
                configData.config = null;
                configData.callBack = clientCreationCallBack;
            } else {
                configData.config = stsClientConfig;
                configData.callBack = null;
            }
            configs.put(key, configData);
            free.put(key, clients);
            inUse.put(key, new ArrayList<STSClient>(numberOfSTSClients));
        } else {
            // free pool already contains given key:
            throw logger.freePoolAlreadyContainsGivenKey(key);
        }

    }

    synchronized void destroy(STSClientConfig stsClientConfig) {
        String key = key(stsClientConfig);
        free.remove(key);
        inUse.remove(key);
        configs.remove(key);
    }

    synchronized void destroy(String moduleName) {
        String module = moduleName;
        if (moduleName == null || moduleName.isEmpty()) {
            module = ModuleUtils.getCurrentModuleId();
        }
        int removed = 0;
        removeByPrefix(module, free);
        removeByPrefix(module, inUse);
        removed += removeByPrefix(module, configs);
        if (removed == 0) {
            // fallback to modified prefix
            module = "deployment." + module;
            removeByPrefix(module, free);
            removeByPrefix(module, inUse);
            removeByPrefix(module, configs);
        }
    }


    STSClient takeOut(STSClientConfig stsClientConfig) {
        String key = key(stsClientConfig);
        return takeOutInternal(key);
    }


    STSClient takeOut(String key) {
        String substKey = substituteKey(key);
        STSClient client = takeOutInternal(substKey);
        if (client == null) {
            STSConfigData configData = configs.get(substKey);
            if (configData == null) {
                throw logger.cannotGetSTSConfigByKey(substKey);
            }
            if (configData.callBack != null) {
                internalInitialize(DEFAULT_NUM_STS_CLIENTS, null, configData.callBack);
            }
            else if (configData.config != null) {
                internalInitialize(DEFAULT_NUM_STS_CLIENTS, configData.config, configData.callBack);
            }
            client = takeOutInternal(substKey);
        }
        return client;
    }

    boolean isConfigInitialized(STSClientConfig stsClientConfig) {
        if (stsClientConfig == null) {
            return false;
         }
        STSConfigData configData = configs.get(key(stsClientConfig));
        return (configData != null);
    }

    boolean isConfigInitialized(String key) {
        if (key == null) {
           return false;
        }
        STSConfigData configData = configs.get(substituteKey(key));
        return (configData != null);
    }

    void putIn(STSClientConfigKeyProvider keyProvider, STSClient client) {
        putInInternal(substituteKey(keyProvider.getSTSClientConfigKey()), client);
    }

    void putIn(String key, STSClient client) {
        putInInternal(substituteKey(key), client);
    }

    void putIn(STSClient client) {
        putInInternal(substituteKey(client.getSTSClientConfigKey()), client);
    }

    private synchronized STSClient takeOutInternal(String key) {
        // no key substitution
        ArrayList<STSClient> clients = free.get(key);
        if (clients != null) {
            int size = clients.size();
            STSClient client;
            if (size > 0) {
                client = clients.remove(size - 1);
            } else {
                addClients(key);
                client = clients.remove(clients.size() -1);
            }
            markInUse(key, client);
            return client;
        }
        return null;
    }

    private void addClients(String key) {
        // no key substitution
        STSConfigData configData = configs.get(key);
        if (configData != null) {
            ArrayList<STSClient> freeClientPool = free.get(key);
            if (freeClientPool != null) {
                ArrayList<STSClient> clients = new ArrayList<STSClient>(configData.initialNumberOfClients);
                if (configData.config != null) {
                    for (int i = 0; i < configData.initialNumberOfClients; i++) {
                        clients.add(new STSClient(configData.config));
                    }
                } else {
                    for (int i = 0; i < configData.initialNumberOfClients; i++) {
                        clients.add(configData.callBack.createClient());
                    }
                }
                freeClientPool.addAll(clients);
            } else {
                // cannot get free client pool key:
                throw logger.cannotGetFreeClientPoolKey(key);
            }
        }  else {
            // cannot get STS config by key:
            throw logger.cannotGetSTSConfigByKey(key);
        }
    }

    private void markInUse(String key, STSClient client) {
        // no key substitution
        ArrayList<STSClient> usedClients = inUse.get(key);
        if (usedClients != null) {
            usedClients.add(client);
        } else {
            // cannot get used clients by key:
            logger.cannotGetUsedClientsByKey(key);
        }
    }

    private synchronized void putInInternal(String key, STSClient client) {
        // no key substitution
        STSConfigData configData = configs.get(key);
        if (configData == null) {
            // attempt to return client not from pool, we can silently ignore it
            return;
        }

        ArrayList<STSClient> freeClients = free.get(key);
        ArrayList<STSClient> usedClients = inUse.get(key);

        if (usedClients != null && !usedClients.remove(client)) {
            // removing non existing client from used clients by key:
            throw logger.removingNonExistingClientFromUsedClientsByKey(key);
        }

        freeClients.add(client);

    }

    private String key(STSClientConfig stsClientConfig) {
        return substituteKey(stsClientConfig.getSTSClientConfigKey());
    }

    private String substituteKey(String originalKey) {
        if (originalKey != null && originalKey.indexOf(STSClientConfig.SUBSTITUTE_MODULE) != -1) {
            return originalKey.replaceAll("\\Q" + STSClientConfig.SUBSTITUTE_MODULE + "\\E", ModuleUtils.getCurrentModuleId());
        }
        return originalKey;
    }

    private int removeByPrefix(String prefix, Hashtable<String, ?> hashTbl) {
        int num = 0;
        Enumeration<String> keys = hashTbl.keys();
        while(keys.hasMoreElements()) {
            String k = keys.nextElement();
            if (k.startsWith(prefix)) {
                num++;
                hashTbl.remove(k);
            }
        }
        return num;
    }

}

class STSConfigData {
    STSClientConfig config;
    STSClientCreationCallBack callBack;
    int initialNumberOfClients = STSClientPoolInternal.DEFAULT_NUM_STS_CLIENTS;
}
