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
package org.picketlink.social.openid.providers;

import javax.xml.namespace.QName;

/**
 * A {@code SecurityTokenProvider} implementation for Open ID v2
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 20, 2011
 */
public class OpenIDVersion2TokenProvider extends OpenIDTokenProvider {

    @Override
    public boolean supports(String namespace) {
        return OPENID_2_0_NS.equals(namespace);
    }

    @Override
    public String tokenType() {
        return OPENID_2_0_NS;
    }

    @Override
    public QName getSupportedQName() {
        return new QName(OPENID_2_0_NS);
    }
}