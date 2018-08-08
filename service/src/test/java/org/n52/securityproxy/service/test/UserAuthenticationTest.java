/*
 * Copyright 2017-2018 52°North Initiative for Geospatial Open Source
 * Software GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.n52.securityproxy.service.test;

import org.junit.Test;
import org.n52.securityproxy.service.util.OAuthUtil;
import org.n52.securityproxy.service.util.SecurityProxyConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthenticationTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserAuthenticationTest.class);

    @Test
    public void testUserAuthentication() {

        SecurityProxyConfiguration.getInstance(getClass().getResourceAsStream("config.json"));

        String token = "9dd58ddf-f4e6-42aa-ac60-500b6e6aae87";

        try {
            String userName = OAuthUtil.getUserNameFromAccessToken(token);

            LOGGER.info("Got user name: " + userName);

        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
    }

}
