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
package org.n52.securityproxy.service.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

/**
 * provides utility methods for OAuth Token parsing and verification; wraps
 * auth0 OAuth Java libs.
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
            String issuer) throws GeneralSecurityException, IOException, TokenExpiredException {
        List<String> scopes = new ArrayList<>();
        DecodedJWT jwt = new TokenDecoder(publicKey).decodeToken(token, issuer);

        String base64EncodedPayload = jwt.getPayload();

        byte[] decodedPayloadByteArray = Base64.getDecoder().decode(base64EncodedPayload);

        ObjectMapper m = new ObjectMapper();

        JsonNode rootNode = m.readTree(new String(decodedPayloadByteArray));

        JsonNode scopeNode = rootNode.findPath("scope");

        String scopeText = scopeNode.textValue();
        String[] scopeArray = scopeText.split(" ");

        for (String scope : scopeArray) {
            scopes.add(scope);
        }

        LOGGER.info(scopeText);
        return scopes;
    }

    public static String getUserNameFromAccessToken(String accessToken){

        String userInfoEndpoint = SecurityProxyConfiguration.getInstance().getUserInfoEndpoint();

        try {
            JsonNode response = getJSONFromURLString(createGetUserInfoURL(userInfoEndpoint, accessToken));

            return getUserNameFromJSON(response);

        } catch (IOException e) {
            LOGGER.error("Could not get JSON from URL: " + userInfoEndpoint, e);
        } catch (OAuthException e) {
            LOGGER.error("Could not get User info from URL: " + userInfoEndpoint + " with token " + accessToken, e);
        }

        return null;

    }

    public static JsonNode getJSONFromURLString(URL url) throws IOException{

        InputStream in = url.openStream();

        ObjectMapper m = new ObjectMapper();

        JsonNode rootNode = m.readTree(in);

        return rootNode;
    }

    public static String getUserNameFromJSON(JsonNode node) throws OAuthException{

       JsonNode errorNode = node.findPath("error");

       if(errorNode != null && !(errorNode instanceof MissingNode)){
           JsonNode errorDescriptionNode = node.findPath("error_description");

           String errorDescription = errorDescriptionNode != null ? errorDescriptionNode.asText() : "No error description returned.";

           throw new OAuthException(401, errorDescription);
       }

       JsonNode userNameNode = node.findPath("user_name");

       if(userNameNode != null && !(userNameNode instanceof MissingNode)){
           return userNameNode.asText();
       }else{
           LOGGER.debug(node.asText());
           throw new OAuthException(401, "User info request failed.");
       }

    }

    public static URL createGetUserInfoURL(String userInfoEndpoint, String token) throws IllegalArgumentException{

        String userInfoURLString = userInfoEndpoint + "?access_token=" + token;

        try {
            URL userInfoURL = new URL(userInfoURLString);
            return userInfoURL;
        } catch (MalformedURLException e) {
            LOGGER.error("Could not create URL from: " + userInfoURLString);
            throw new IllegalArgumentException("URL not valid: " + userInfoURLString);
        }

    }

}
