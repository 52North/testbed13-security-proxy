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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class TokenDecoder {

    private static Logger LOGGER = LoggerFactory.getLogger(TokenDecoder.class);

    private String encodedPublicKey;

    public TokenDecoder(String publicKeyPath) {

        try {
            encodedPublicKey = readFile(publicKeyPath);
        } catch (IOException e) {
            LOGGER.error("Could not decode public key.", e);
        }
    }

    public TokenDecoder(InputStream in) {

        try {
            encodedPublicKey = readStream(in);
        } catch (IOException e) {
            LOGGER.error("Could not decode public key.", e);
        }
    }

    public DecodedJWT decodeToken(String token,
            String issuer) throws GeneralSecurityException, TokenExpiredException {

        DecodedJWT decodedToken = null;
        RSAPublicKey publicKey = newRsaPublicKey();

        Algorithm algorithm = Algorithm.RSA256(publicKey, null);

        JWTVerifier verifier = JWT.require(algorithm).withIssuer(issuer).build();

        decodedToken = verifier.verify(token);

        return decodedToken;
    }

    /**
     * Returns a new RSAPublicKey object
     *
     * @return RSAPublicKey
     *
     * @throws GeneralSecurityException
     *             if decoding fails.
     */
    public RSAPublicKey newRsaPublicKey() throws GeneralSecurityException {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        KeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey));

        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    private String readFile(String fileName) throws IOException {

        return readStream(new FileInputStream(new File(fileName)));
    }

    private String readStream(InputStream in) throws IOException {

        String content = "";

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));

        String line = "";

        while ((line = bufferedReader.readLine()) != null) {
            content = content.concat(line);
        }

        bufferedReader.close();

        return content;
    }

}
