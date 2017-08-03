/*
 * Copyright 2017-2017 52°North Initiative for Geospatial Open Source
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
package org.n52.securityproxy.service.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.n52.geoprocessing.oauth2.TokenDecoder;
import org.n52.securityproxy.service.handler.OAuthHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * provides utility methods for OAuth Token parsing and verification; wraps auth0 OAuth Java libs.
 *
 * @author staschc
 *
 */
public class OAuthUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthUtil.class);

    /**
     * verifies token and returns scopes extracted form token
     *
     * @param publicKey
     *            publicKey for verifying token
     * @param token
     *            OAuth Access token
     * @param issuer
     *            issuer of the request
     * @return list of scopes
     * @throws java.security.GeneralSecurityException
     *             if verification of token fails
     * @throws java.io.IOException
     *             if parsing token payload fails
     */
    public static List<String> getScopesFromToken(InputStream publicKey,
            String token,
            String issuer) throws GeneralSecurityException, IOException {
        List<String> scopes = new ArrayList<>();
        DecodedJWT jwt = new TokenDecoder(publicKey).decodeToken(token, issuer);

        String base64EncodedPayload = jwt.getPayload();

        byte[] decodedPayloadByteArray = Base64.getDecoder().decode(base64EncodedPayload);

        ObjectMapper m = new ObjectMapper();

        JsonNode rootNode = m.readTree(new String(decodedPayloadByteArray));

        JsonNode scopeNode = rootNode.findPath("scope");

        String scopeText = scopeNode.textValue();
        String[] scopeArray = scopeText.split(" ");

        for (String scope:scopeArray){
            scopes.add(scope);
        }

        LOGGER.info(scopeText);
        return scopes;
    }

}
