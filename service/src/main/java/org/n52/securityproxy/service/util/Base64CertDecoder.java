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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Base64CertDecoder {

    private X509Certificate certificate;

    public Base64CertDecoder() {
    }

    public Base64CertDecoder decodeBase64EndodedCertificateString(String base64EncodedCertificate)
            throws CertificateException, KeyStoreException, NoSuchAlgorithmException, java.security.cert.CertificateException, IOException {

        KeyStore clientCertificate = KeyStore.getInstance("pkcs12");

        byte[] encodedCert = Base64.getDecoder().decode(base64EncodedCertificate.trim());

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);

        clientCertificate.load(inputStream, "changeit".toCharArray());

        if (clientCertificate.aliases() != null && clientCertificate.aliases().hasMoreElements()) {

            String alias = clientCertificate.aliases().nextElement();

            Certificate certificate = clientCertificate.getCertificate(alias);

            if (certificate instanceof X509Certificate) {
                this.certificate = (X509Certificate) certificate;
            }
        }
        return this;
    }

    public Base64CertDecoder decodeBase64EndodedClientCertificateString(String base64EncodedCertificate)
            throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {

        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(base64EncodedCertificate.getBytes());

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate)certFactory.generateCertificate(inputStream);
        return this;
    }

    public String getPrincipalCN() {

        Principal principal = this.certificate.getSubjectDN();

        String principalName = "";

        if (principal != null) {
            principalName = principal.getName();
        } else {
            throw new IllegalArgumentException("Certificate has no principal.");
        }

        Pattern pattern = Pattern.compile("CN=(.*?),");

        Matcher matcher = pattern.matcher(principalName);

        if (matcher.find()) {
            return matcher.group(1);
        }

        return "";
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
